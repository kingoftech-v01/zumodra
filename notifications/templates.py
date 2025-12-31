"""
Predefined notification types and their default templates.

This module provides constants and default templates for common notification types
used throughout the Zumodra platform.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class NotificationType(str, Enum):
    """Enumeration of all notification types."""

    # HR & Recruitment
    APPLICATION_RECEIVED = 'application_received'
    APPLICATION_REVIEWED = 'application_reviewed'
    INTERVIEW_SCHEDULED = 'interview_scheduled'
    INTERVIEW_REMINDER = 'interview_reminder'
    INTERVIEW_CANCELLED = 'interview_cancelled'
    OFFER_SENT = 'offer_sent'
    OFFER_ACCEPTED = 'offer_accepted'
    OFFER_DECLINED = 'offer_declined'
    ONBOARDING_TASK_DUE = 'onboarding_task_due'
    ONBOARDING_COMPLETE = 'onboarding_complete'

    # Time & Attendance
    TIME_OFF_REQUESTED = 'time_off_requested'
    TIME_OFF_APPROVED = 'time_off_approved'
    TIME_OFF_DENIED = 'time_off_denied'
    TIMESHEET_REMINDER = 'timesheet_reminder'
    TIMESHEET_APPROVED = 'timesheet_approved'

    # Services & Contracts
    PROPOSAL_RECEIVED = 'proposal_received'
    PROPOSAL_ACCEPTED = 'proposal_accepted'
    PROPOSAL_REJECTED = 'proposal_rejected'
    CONTRACT_CREATED = 'contract_created'
    CONTRACT_SIGNED = 'contract_signed'
    CONTRACT_COMPLETED = 'contract_completed'
    CONTRACT_CANCELLED = 'contract_cancelled'

    # Payments & Finance
    PAYMENT_RECEIVED = 'payment_received'
    PAYMENT_SENT = 'payment_sent'
    PAYMENT_FAILED = 'payment_failed'
    INVOICE_GENERATED = 'invoice_generated'
    ESCROW_FUNDED = 'escrow_funded'
    ESCROW_RELEASED = 'escrow_released'
    REFUND_PROCESSED = 'refund_processed'

    # Reviews & Ratings
    REVIEW_RECEIVED = 'review_received'
    REVIEW_RESPONSE = 'review_response'

    # Messages & Communication
    NEW_MESSAGE = 'new_message'
    MESSAGE_REPLY = 'message_reply'

    # Appointments
    APPOINTMENT_BOOKED = 'appointment_booked'
    APPOINTMENT_REMINDER = 'appointment_reminder'
    APPOINTMENT_CANCELLED = 'appointment_cancelled'
    APPOINTMENT_RESCHEDULED = 'appointment_rescheduled'

    # Account & Security
    ACCOUNT_CREATED = 'account_created'
    PASSWORD_CHANGED = 'password_changed'
    LOGIN_ALERT = 'login_alert'
    TWO_FACTOR_ENABLED = 'two_factor_enabled'
    ACCOUNT_SUSPENDED = 'account_suspended'
    ACCOUNT_REACTIVATED = 'account_reactivated'

    # System & Administrative
    SYSTEM_MAINTENANCE = 'system_maintenance'
    FEATURE_ANNOUNCEMENT = 'feature_announcement'
    POLICY_UPDATE = 'policy_update'

    # Marketing & Engagement
    WELCOME_EMAIL = 'welcome_email'
    WEEKLY_DIGEST = 'weekly_digest'
    DAILY_DIGEST = 'daily_digest'
    PROMOTIONAL = 'promotional'
    EVENT_INVITATION = 'event_invitation'

    # Custom
    CUSTOM = 'custom'


@dataclass
class NotificationTemplateData:
    """Data structure for notification template configuration."""
    type: NotificationType
    name: str
    description: str
    default_subject: str
    default_body: str
    default_html_body: str
    available_context_vars: List[str]
    default_channels: List[str]
    priority: str = 'normal'


# Default notification templates
DEFAULT_TEMPLATES: Dict[str, NotificationTemplateData] = {
    # HR & Recruitment Templates
    NotificationType.APPLICATION_RECEIVED.value: NotificationTemplateData(
        type=NotificationType.APPLICATION_RECEIVED,
        name="Application Received",
        description="Sent to hiring managers when a new application is received",
        default_subject="New Application: {{ position_title }}",
        default_body="""Hello {{ recipient.first_name }},

A new application has been received for the {{ position_title }} position.

Applicant: {{ applicant_name }}
Applied: {{ applied_at }}

Please review the application at your earliest convenience.

Best regards,
The {{ company_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>New Application Received</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>A new application has been received for the <strong>{{ position_title }}</strong> position.</p>
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Applicant:</strong> {{ applicant_name }}</p>
        <p><strong>Applied:</strong> {{ applied_at }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Review Application</a></p>
    <p>Best regards,<br>The {{ company_name }} Team</p>
</body>
</html>""",
        available_context_vars=['position_title', 'applicant_name', 'applied_at', 'company_name'],
        default_channels=['email', 'in_app'],
        priority='normal',
    ),

    NotificationType.INTERVIEW_SCHEDULED.value: NotificationTemplateData(
        type=NotificationType.INTERVIEW_SCHEDULED,
        name="Interview Scheduled",
        description="Sent to candidates when an interview is scheduled",
        default_subject="Interview Scheduled: {{ position_title }}",
        default_body="""Hello {{ recipient.first_name }},

Great news! Your interview has been scheduled.

Position: {{ position_title }}
Date: {{ interview_date }}
Time: {{ interview_time }}
Location: {{ interview_location }}
Interviewer: {{ interviewer_name }}

Please confirm your attendance by clicking the link below.

Best regards,
The {{ company_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Interview Scheduled!</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>Great news! Your interview has been scheduled.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Position:</strong> {{ position_title }}</p>
        <p><strong>Date:</strong> {{ interview_date }}</p>
        <p><strong>Time:</strong> {{ interview_time }}</p>
        <p><strong>Location:</strong> {{ interview_location }}</p>
        <p><strong>Interviewer:</strong> {{ interviewer_name }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirm Attendance</a></p>
    <p>Best regards,<br>The {{ company_name }} Team</p>
</body>
</html>""",
        available_context_vars=['position_title', 'interview_date', 'interview_time', 'interview_location', 'interviewer_name', 'company_name'],
        default_channels=['email', 'sms', 'in_app'],
        priority='high',
    ),

    NotificationType.OFFER_SENT.value: NotificationTemplateData(
        type=NotificationType.OFFER_SENT,
        name="Job Offer Sent",
        description="Sent to candidates when they receive a job offer",
        default_subject="Job Offer: {{ position_title }} at {{ company_name }}",
        default_body="""Hello {{ recipient.first_name }},

Congratulations! We are pleased to extend an offer for the {{ position_title }} position.

Salary: {{ salary }}
Start Date: {{ start_date }}
Benefits: {{ benefits }}

Please review the offer and respond by {{ deadline }}.

Best regards,
The {{ company_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Congratulations! Job Offer</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>We are pleased to extend an offer for the <strong>{{ position_title }}</strong> position at {{ company_name }}.</p>
    <div style="background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Salary:</strong> {{ salary }}</p>
        <p><strong>Start Date:</strong> {{ start_date }}</p>
        <p><strong>Benefits:</strong> {{ benefits }}</p>
        <p><strong>Response Deadline:</strong> {{ deadline }}</p>
    </div>
    <p>
        <a href="{{ action_url }}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">Accept Offer</a>
        <a href="{{ decline_url }}" style="background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Decline</a>
    </p>
    <p>Best regards,<br>The {{ company_name }} Team</p>
</body>
</html>""",
        available_context_vars=['position_title', 'salary', 'start_date', 'benefits', 'deadline', 'company_name', 'decline_url'],
        default_channels=['email', 'in_app'],
        priority='urgent',
    ),

    NotificationType.TIME_OFF_APPROVED.value: NotificationTemplateData(
        type=NotificationType.TIME_OFF_APPROVED,
        name="Time Off Approved",
        description="Sent to employees when their time off request is approved",
        default_subject="Time Off Request Approved",
        default_body="""Hello {{ recipient.first_name }},

Your time off request has been approved!

Dates: {{ start_date }} - {{ end_date }}
Type: {{ leave_type }}
Approved by: {{ approver_name }}

Enjoy your time off!

Best regards,
The {{ company_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Time Off Approved!</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>Your time off request has been approved.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Dates:</strong> {{ start_date }} - {{ end_date }}</p>
        <p><strong>Type:</strong> {{ leave_type }}</p>
        <p><strong>Approved by:</strong> {{ approver_name }}</p>
    </div>
    <p>Enjoy your time off!</p>
    <p>Best regards,<br>The {{ company_name }} Team</p>
</body>
</html>""",
        available_context_vars=['start_date', 'end_date', 'leave_type', 'approver_name', 'company_name'],
        default_channels=['email', 'in_app', 'push'],
        priority='normal',
    ),

    NotificationType.ONBOARDING_TASK_DUE.value: NotificationTemplateData(
        type=NotificationType.ONBOARDING_TASK_DUE,
        name="Onboarding Task Due",
        description="Reminder for pending onboarding tasks",
        default_subject="Reminder: {{ task_name }} is due {{ due_date }}",
        default_body="""Hello {{ recipient.first_name }},

This is a reminder that the following onboarding task is due soon:

Task: {{ task_name }}
Due Date: {{ due_date }}
Description: {{ task_description }}

Please complete this task to continue your onboarding process.

Best regards,
The {{ company_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Onboarding Task Reminder</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>This is a reminder that the following onboarding task is due soon:</p>
    <div style="background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Task:</strong> {{ task_name }}</p>
        <p><strong>Due Date:</strong> {{ due_date }}</p>
        <p><strong>Description:</strong> {{ task_description }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Complete Task</a></p>
    <p>Best regards,<br>The {{ company_name }} Team</p>
</body>
</html>""",
        available_context_vars=['task_name', 'due_date', 'task_description', 'company_name'],
        default_channels=['email', 'in_app', 'push'],
        priority='high',
    ),

    # Services & Contracts Templates
    NotificationType.PROPOSAL_RECEIVED.value: NotificationTemplateData(
        type=NotificationType.PROPOSAL_RECEIVED,
        name="New Proposal Received",
        description="Sent to clients when a service provider submits a proposal",
        default_subject="New Proposal: {{ service_title }}",
        default_body="""Hello {{ recipient.first_name }},

You have received a new proposal for your service request.

Service: {{ service_title }}
Provider: {{ provider_name }}
Price: {{ proposed_price }}
Delivery Time: {{ delivery_time }}

Review and respond to this proposal at your convenience.

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>New Proposal Received</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>You have received a new proposal for your service request.</p>
    <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Service:</strong> {{ service_title }}</p>
        <p><strong>Provider:</strong> {{ provider_name }}</p>
        <p><strong>Price:</strong> {{ proposed_price }}</p>
        <p><strong>Delivery Time:</strong> {{ delivery_time }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Proposal</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['service_title', 'provider_name', 'proposed_price', 'delivery_time'],
        default_channels=['email', 'in_app'],
        priority='normal',
    ),

    NotificationType.CONTRACT_CREATED.value: NotificationTemplateData(
        type=NotificationType.CONTRACT_CREATED,
        name="Contract Created",
        description="Sent when a new contract is created",
        default_subject="New Contract: {{ contract_title }}",
        default_body="""Hello {{ recipient.first_name }},

A new contract has been created for your review.

Contract: {{ contract_title }}
Amount: {{ contract_amount }}
Duration: {{ contract_duration }}
Start Date: {{ start_date }}

Please review and sign the contract.

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>New Contract Created</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>A new contract has been created for your review.</p>
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Contract:</strong> {{ contract_title }}</p>
        <p><strong>Amount:</strong> {{ contract_amount }}</p>
        <p><strong>Duration:</strong> {{ contract_duration }}</p>
        <p><strong>Start Date:</strong> {{ start_date }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Review Contract</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['contract_title', 'contract_amount', 'contract_duration', 'start_date'],
        default_channels=['email', 'in_app'],
        priority='high',
    ),

    # Payment Templates
    NotificationType.PAYMENT_RECEIVED.value: NotificationTemplateData(
        type=NotificationType.PAYMENT_RECEIVED,
        name="Payment Received",
        description="Sent when a payment is received",
        default_subject="Payment Received: {{ amount }}",
        default_body="""Hello {{ recipient.first_name }},

You have received a payment.

Amount: {{ amount }}
From: {{ payer_name }}
Reference: {{ payment_reference }}
Date: {{ payment_date }}

The funds have been added to your account.

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Payment Received!</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>You have received a payment.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Amount:</strong> {{ amount }}</p>
        <p><strong>From:</strong> {{ payer_name }}</p>
        <p><strong>Reference:</strong> {{ payment_reference }}</p>
        <p><strong>Date:</strong> {{ payment_date }}</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Transaction</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['amount', 'payer_name', 'payment_reference', 'payment_date'],
        default_channels=['email', 'in_app', 'push'],
        priority='high',
    ),

    NotificationType.ESCROW_FUNDED.value: NotificationTemplateData(
        type=NotificationType.ESCROW_FUNDED,
        name="Escrow Funded",
        description="Sent when escrow is funded for a contract",
        default_subject="Escrow Funded: {{ contract_title }}",
        default_body="""Hello {{ recipient.first_name }},

The escrow for your contract has been funded.

Contract: {{ contract_title }}
Amount: {{ escrow_amount }}
Status: Funds secured

You can now begin work on this project.

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Escrow Funded</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>The escrow for your contract has been funded.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Contract:</strong> {{ contract_title }}</p>
        <p><strong>Amount:</strong> {{ escrow_amount }}</p>
        <p><strong>Status:</strong> Funds secured</p>
    </div>
    <p>You can now begin work on this project.</p>
    <p><a href="{{ action_url }}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Contract</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['contract_title', 'escrow_amount'],
        default_channels=['email', 'in_app'],
        priority='high',
    ),

    # Appointment Templates
    NotificationType.APPOINTMENT_BOOKED.value: NotificationTemplateData(
        type=NotificationType.APPOINTMENT_BOOKED,
        name="Appointment Booked",
        description="Sent when an appointment is booked",
        default_subject="Appointment Confirmed: {{ service_name }}",
        default_body="""Hello {{ recipient.first_name }},

Your appointment has been confirmed.

Service: {{ service_name }}
Date: {{ appointment_date }}
Time: {{ appointment_time }}
Duration: {{ duration }}
Location: {{ location }}

Add this to your calendar to ensure you don't miss it!

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Appointment Confirmed</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>Your appointment has been confirmed.</p>
    <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Service:</strong> {{ service_name }}</p>
        <p><strong>Date:</strong> {{ appointment_date }}</p>
        <p><strong>Time:</strong> {{ appointment_time }}</p>
        <p><strong>Duration:</strong> {{ duration }}</p>
        <p><strong>Location:</strong> {{ location }}</p>
    </div>
    <p>
        <a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">View Details</a>
        <a href="{{ calendar_url }}" style="background: #6c757d; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Add to Calendar</a>
    </p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['service_name', 'appointment_date', 'appointment_time', 'duration', 'location', 'calendar_url'],
        default_channels=['email', 'sms', 'in_app'],
        priority='high',
    ),

    NotificationType.APPOINTMENT_REMINDER.value: NotificationTemplateData(
        type=NotificationType.APPOINTMENT_REMINDER,
        name="Appointment Reminder",
        description="Reminder before scheduled appointment",
        default_subject="Reminder: Appointment Tomorrow - {{ service_name }}",
        default_body="""Hello {{ recipient.first_name }},

This is a reminder about your upcoming appointment.

Service: {{ service_name }}
Date: {{ appointment_date }}
Time: {{ appointment_time }}
Location: {{ location }}

See you soon!

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Appointment Reminder</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>This is a reminder about your upcoming appointment.</p>
    <div style="background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Service:</strong> {{ service_name }}</p>
        <p><strong>Date:</strong> {{ appointment_date }}</p>
        <p><strong>Time:</strong> {{ appointment_time }}</p>
        <p><strong>Location:</strong> {{ location }}</p>
    </div>
    <p>See you soon!</p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['service_name', 'appointment_date', 'appointment_time', 'location'],
        default_channels=['email', 'sms', 'push'],
        priority='high',
    ),

    # Account & Security Templates
    NotificationType.ACCOUNT_CREATED.value: NotificationTemplateData(
        type=NotificationType.ACCOUNT_CREATED,
        name="Welcome - Account Created",
        description="Sent when a new account is created",
        default_subject="Welcome to {{ platform_name }}!",
        default_body="""Hello {{ recipient.first_name }},

Welcome to {{ platform_name }}!

Your account has been successfully created. Here's what you can do next:

1. Complete your profile
2. Explore available services
3. Connect with providers

If you have any questions, our support team is here to help.

Best regards,
The {{ platform_name }} Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Welcome to {{ platform_name }}!</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>Your account has been successfully created.</p>
    <h3>Here's what you can do next:</h3>
    <ol>
        <li>Complete your profile</li>
        <li>Explore available services</li>
        <li>Connect with providers</li>
    </ol>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Get Started</a></p>
    <p>If you have any questions, our support team is here to help.</p>
    <p>Best regards,<br>The {{ platform_name }} Team</p>
</body>
</html>""",
        available_context_vars=['platform_name'],
        default_channels=['email'],
        priority='normal',
    ),

    NotificationType.LOGIN_ALERT.value: NotificationTemplateData(
        type=NotificationType.LOGIN_ALERT,
        name="New Login Alert",
        description="Security alert for new login from unknown device/location",
        default_subject="Security Alert: New Login Detected",
        default_body="""Hello {{ recipient.first_name }},

We detected a new login to your account.

Device: {{ device_info }}
Location: {{ location }}
Time: {{ login_time }}
IP Address: {{ ip_address }}

If this was you, you can ignore this message.

If you didn't log in, please secure your account immediately.

Best regards,
The Security Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Security Alert: New Login Detected</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>We detected a new login to your account.</p>
    <div style="background: #ffebee; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Device:</strong> {{ device_info }}</p>
        <p><strong>Location:</strong> {{ location }}</p>
        <p><strong>Time:</strong> {{ login_time }}</p>
        <p><strong>IP Address:</strong> {{ ip_address }}</p>
    </div>
    <p>If this was you, you can ignore this message.</p>
    <p>If you didn't log in, please secure your account immediately:</p>
    <p><a href="{{ action_url }}" style="background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Secure My Account</a></p>
    <p>Best regards,<br>The Security Team</p>
</body>
</html>""",
        available_context_vars=['device_info', 'location', 'login_time', 'ip_address'],
        default_channels=['email', 'push'],
        priority='urgent',
    ),

    # Messaging Templates
    NotificationType.NEW_MESSAGE.value: NotificationTemplateData(
        type=NotificationType.NEW_MESSAGE,
        name="New Message",
        description="Sent when user receives a new message",
        default_subject="New message from {{ sender_name }}",
        default_body="""Hello {{ recipient.first_name }},

You have a new message from {{ sender_name }}.

"{{ message_preview }}..."

Reply to continue the conversation.

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>New Message</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>You have a new message from <strong>{{ sender_name }}</strong>.</p>
    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #007bff;">
        <p style="font-style: italic;">"{{ message_preview }}..."</p>
    </div>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reply</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['sender_name', 'message_preview'],
        default_channels=['email', 'push', 'in_app'],
        priority='normal',
    ),

    # Review Templates
    NotificationType.REVIEW_RECEIVED.value: NotificationTemplateData(
        type=NotificationType.REVIEW_RECEIVED,
        name="New Review Received",
        description="Sent when user receives a new review",
        default_subject="You received a {{ rating }}-star review!",
        default_body="""Hello {{ recipient.first_name }},

You have received a new review!

Rating: {{ rating }} stars
From: {{ reviewer_name }}
Service: {{ service_name }}

"{{ review_text }}"

Thank you for your excellent service!

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>New Review Received!</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>You have received a new review!</p>
    <div style="background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Rating:</strong> {{ rating }} stars</p>
        <p><strong>From:</strong> {{ reviewer_name }}</p>
        <p><strong>Service:</strong> {{ service_name }}</p>
        <p style="font-style: italic;">"{{ review_text }}"</p>
    </div>
    <p>Thank you for your excellent service!</p>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Review</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['rating', 'reviewer_name', 'service_name', 'review_text'],
        default_channels=['email', 'in_app'],
        priority='normal',
    ),

    # Digest Templates
    NotificationType.WEEKLY_DIGEST.value: NotificationTemplateData(
        type=NotificationType.WEEKLY_DIGEST,
        name="Weekly Digest",
        description="Weekly summary of activity",
        default_subject="Your Weekly Summary - {{ week_start }} to {{ week_end }}",
        default_body="""Hello {{ recipient.first_name }},

Here's your weekly summary:

New Messages: {{ new_messages_count }}
New Proposals: {{ new_proposals_count }}
Completed Contracts: {{ completed_contracts_count }}
Earnings: {{ total_earnings }}

Keep up the great work!

Best regards,
The Zumodra Team""",
        default_html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <h2>Your Weekly Summary</h2>
    <p>Hello {{ recipient.first_name }},</p>
    <p>Here's what happened this week ({{ week_start }} - {{ week_end }}):</p>
    <div style="display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0;">
        <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; text-align: center;">
            <h3 style="margin: 0;">{{ new_messages_count }}</h3>
            <p style="margin: 5px 0 0;">New Messages</p>
        </div>
        <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; text-align: center;">
            <h3 style="margin: 0;">{{ new_proposals_count }}</h3>
            <p style="margin: 5px 0 0;">New Proposals</p>
        </div>
        <div style="background: #fff3e0; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; text-align: center;">
            <h3 style="margin: 0;">{{ completed_contracts_count }}</h3>
            <p style="margin: 5px 0 0;">Completed</p>
        </div>
        <div style="background: #f3e5f5; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; text-align: center;">
            <h3 style="margin: 0;">{{ total_earnings }}</h3>
            <p style="margin: 5px 0 0;">Earnings</p>
        </div>
    </div>
    <p>Keep up the great work!</p>
    <p><a href="{{ action_url }}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Dashboard</a></p>
    <p>Best regards,<br>The Zumodra Team</p>
</body>
</html>""",
        available_context_vars=['week_start', 'week_end', 'new_messages_count', 'new_proposals_count', 'completed_contracts_count', 'total_earnings'],
        default_channels=['email'],
        priority='low',
    ),
}


def get_template_data(notification_type: str) -> Optional[NotificationTemplateData]:
    """Get the template data for a notification type."""
    return DEFAULT_TEMPLATES.get(notification_type)


def get_all_template_types() -> List[str]:
    """Get all available notification types."""
    return list(DEFAULT_TEMPLATES.keys())


def get_default_channels(notification_type: str) -> List[str]:
    """Get the default channels for a notification type."""
    template = get_template_data(notification_type)
    return template.default_channels if template else ['in_app']


def get_priority(notification_type: str) -> str:
    """Get the default priority for a notification type."""
    template = get_template_data(notification_type)
    return template.priority if template else 'normal'
