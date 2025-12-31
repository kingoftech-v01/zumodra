"""
Notification Signals - Auto-create notifications for various events.

Connects to Django signals from other apps to trigger notifications.
"""

import logging
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from .services import notification_service
from .models import NotificationPreference

logger = logging.getLogger(__name__)
User = get_user_model()


# ==================== User Account Signals ====================

@receiver(post_save, sender=User)
def create_notification_preferences(sender, instance, created, **kwargs):
    """Create notification preferences when a new user is created."""
    if created:
        NotificationPreference.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def notify_account_created(sender, instance, created, **kwargs):
    """Send welcome notification when a new user is created."""
    if created:
        try:
            notification_service.send_notification(
                recipient=instance,
                notification_type='account_created',
                title='Welcome to Zumodra!',
                message='Your account has been successfully created. Start exploring our platform!',
                channels=['email', 'in_app'],
                action_url='/dashboard/',
                action_text='Get Started',
                context_data={
                    'platform_name': 'Zumodra',
                },
                priority='normal',
            )
        except Exception as e:
            logger.error(f"Failed to send welcome notification to user {instance.id}: {e}")


# ==================== Service Proposal Signals ====================

def connect_proposal_signals():
    """Connect proposal-related signals if services app is available."""
    try:
        from services.models import ServiceProposal

        @receiver(post_save, sender=ServiceProposal)
        def notify_on_proposal(sender, instance, created, **kwargs):
            """Notify client when a new proposal is submitted."""
            if created:
                try:
                    client = instance.client_request.client

                    notification_service.send_notification(
                        recipient=client,
                        notification_type='proposal_received',
                        title='New Proposal Received',
                        message=f'{instance.provider.display_name} submitted a proposal for your request "{instance.client_request.title}"',
                        sender=instance.provider.user,
                        channels=['email', 'in_app', 'push'],
                        action_url=f'/services/request/{instance.client_request.uuid}/',
                        action_text='View Proposal',
                        context_data={
                            'service_title': instance.client_request.title,
                            'provider_name': instance.provider.display_name,
                            'proposed_rate': str(instance.proposed_rate),
                            'estimated_duration': str(instance.estimated_duration) if instance.estimated_duration else 'TBD',
                        },
                        content_object=instance,
                        priority='normal',
                    )
                except Exception as e:
                    logger.error(f"Failed to send proposal notification: {e}")

        @receiver(post_save, sender=ServiceProposal)
        def notify_on_proposal_accepted(sender, instance, created, **kwargs):
            """Notify provider when their proposal is accepted."""
            if not created and instance.status == 'accepted':
                try:
                    provider = instance.provider.user

                    notification_service.send_notification(
                        recipient=provider,
                        notification_type='proposal_accepted',
                        title='Proposal Accepted!',
                        message=f'Your proposal for "{instance.client_request.title}" has been accepted!',
                        sender=instance.client_request.client,
                        channels=['email', 'in_app', 'push'],
                        action_url='/services/contracts/',
                        action_text='View Contract',
                        context_data={
                            'service_title': instance.client_request.title,
                        },
                        content_object=instance,
                        priority='high',
                    )
                except Exception as e:
                    logger.error(f"Failed to send proposal accepted notification: {e}")

    except ImportError:
        logger.debug("Services app not available, skipping proposal signals")


# ==================== Contract Signals ====================

def connect_contract_signals():
    """Connect contract-related signals if services app is available."""
    try:
        from services.models import ServiceContract

        @receiver(post_save, sender=ServiceContract)
        def notify_on_contract_status_change(sender, instance, created, **kwargs):
            """Notify users when contract status changes."""
            try:
                if created:
                    # Notify provider about new contract
                    provider = instance.provider.user

                    notification_service.send_notification(
                        recipient=provider,
                        notification_type='contract_created',
                        title='New Contract Created',
                        message='A new contract has been created for your service',
                        sender=instance.client,
                        channels=['email', 'in_app'],
                        action_url=f'/services/contract/{instance.id}/',
                        action_text='View Contract',
                        context_data={
                            'contract_title': instance.title if instance.title else 'Service Contract',
                        },
                        content_object=instance,
                        priority='high',
                    )
                else:
                    # Status changed - notify both parties
                    if instance.status == 'active':
                        notification_service.send_notification(
                            recipient=instance.client,
                            notification_type='contract_signed',
                            title='Contract Activated',
                            message=f'Your contract with {instance.provider.display_name} is now active',
                            channels=['email', 'in_app'],
                            action_url=f'/services/contract/{instance.id}/',
                            action_text='View Contract',
                            content_object=instance,
                            priority='high',
                        )

                    elif instance.status == 'completed':
                        notification_service.send_notification(
                            recipient=instance.client,
                            notification_type='contract_completed',
                            title='Contract Completed',
                            message=f'Your contract with {instance.provider.display_name} has been completed',
                            channels=['email', 'in_app'],
                            action_url=f'/services/contract/{instance.id}/',
                            action_text='Leave Review',
                            content_object=instance,
                            priority='normal',
                        )

            except Exception as e:
                logger.error(f"Failed to send contract notification: {e}")

    except ImportError:
        logger.debug("Services app not available, skipping contract signals")


# ==================== Review Signals ====================

def connect_review_signals():
    """Connect review-related signals if services app is available."""
    try:
        from services.models import ServiceReview

        @receiver(post_save, sender=ServiceReview)
        def notify_on_review(sender, instance, created, **kwargs):
            """Notify provider when they receive a review."""
            if created:
                try:
                    provider = instance.provider.user

                    notification_service.send_notification(
                        recipient=provider,
                        notification_type='review_received',
                        title='New Review Received',
                        message=f'You received a {instance.rating}-star review: "{instance.content[:100]}"',
                        sender=instance.reviewer,
                        channels=['email', 'in_app'],
                        action_url=f'/services/contract/{instance.contract.id}/' if instance.contract else '/services/',
                        action_text='View Review',
                        context_data={
                            'rating': instance.rating,
                            'reviewer_name': instance.reviewer.get_full_name() or instance.reviewer.username,
                            'contract_title': instance.contract.title if instance.contract else 'Your Service',
                            'review_text': instance.content[:200],
                        },
                        content_object=instance,
                        priority='normal',
                    )
                except Exception as e:
                    logger.error(f"Failed to send review notification: {e}")

    except ImportError:
        logger.debug("Services app not available, skipping review signals")


# ==================== Payment Signals ====================

def connect_payment_signals():
    """Connect payment-related signals if finance app is available."""
    try:
        from finance.models import Payment, EscrowTransaction

        @receiver(post_save, sender=Payment)
        def notify_on_payment(sender, instance, created, **kwargs):
            """Notify users when a payment is processed."""
            if created and instance.status == 'completed':
                try:
                    # Notify recipient
                    notification_service.send_notification(
                        recipient=instance.recipient,
                        notification_type='payment_received',
                        title='Payment Received',
                        message=f'You received a payment of {instance.amount}',
                        sender=instance.payer,
                        channels=['email', 'in_app', 'push'],
                        action_url='/finance/transactions/',
                        action_text='View Transaction',
                        context_data={
                            'amount': str(instance.amount),
                            'payer_name': instance.payer.get_full_name() or instance.payer.username,
                            'payment_reference': instance.reference or instance.id,
                            'payment_date': instance.created_at.strftime('%B %d, %Y'),
                        },
                        content_object=instance,
                        priority='high',
                    )
                except Exception as e:
                    logger.error(f"Failed to send payment notification: {e}")

        @receiver(post_save, sender=EscrowTransaction)
        def notify_on_escrow(sender, instance, created, **kwargs):
            """Notify users about escrow transactions."""
            if created:
                try:
                    if instance.transaction_type == 'fund':
                        # Notify provider that escrow is funded
                        notification_service.send_notification(
                            recipient=instance.provider.user,
                            notification_type='escrow_funded',
                            title='Escrow Funded',
                            message=f'Escrow of {instance.amount} has been funded for your contract',
                            channels=['email', 'in_app'],
                            action_url=f'/services/contract/{instance.contract_id}/',
                            action_text='View Contract',
                            context_data={
                                'escrow_amount': str(instance.amount),
                                'contract_title': instance.contract.title if hasattr(instance.contract, 'title') else 'Contract',
                            },
                            content_object=instance,
                            priority='high',
                        )
                    elif instance.transaction_type == 'release':
                        # Notify provider that escrow is released
                        notification_service.send_notification(
                            recipient=instance.provider.user,
                            notification_type='escrow_released',
                            title='Escrow Released',
                            message=f'Escrow of {instance.amount} has been released to your account',
                            channels=['email', 'in_app', 'push'],
                            action_url='/finance/transactions/',
                            action_text='View Transaction',
                            context_data={
                                'escrow_amount': str(instance.amount),
                            },
                            content_object=instance,
                            priority='high',
                        )
                except Exception as e:
                    logger.error(f"Failed to send escrow notification: {e}")

    except ImportError:
        logger.debug("Finance app not available, skipping payment signals")


# ==================== Message Signals ====================

def connect_message_signals():
    """Connect message-related signals if messages_sys app is available."""
    try:
        from messages_sys.models import Message

        @receiver(post_save, sender=Message)
        def notify_on_new_message(sender, instance, created, **kwargs):
            """Notify user when they receive a new message."""
            if created:
                try:
                    # Get all recipients from the conversation except sender
                    conversation = instance.conversation
                    recipients = conversation.participants.exclude(id=instance.sender_id)

                    for recipient in recipients:
                        notification_service.send_notification(
                            recipient=recipient,
                            notification_type='new_message',
                            title=f'New message from {instance.sender.get_full_name() or instance.sender.username}',
                            message=instance.content[:100] + ('...' if len(instance.content) > 100 else ''),
                            sender=instance.sender,
                            channels=['in_app', 'push'],  # Email handled by digest
                            action_url=f'/messages/{conversation.id}/',
                            action_text='Reply',
                            context_data={
                                'sender_name': instance.sender.get_full_name() or instance.sender.username,
                                'message_preview': instance.content[:100],
                            },
                            content_object=instance,
                            priority='normal',
                        )
                except Exception as e:
                    logger.error(f"Failed to send message notification: {e}")

    except ImportError:
        logger.debug("Messages app not available, skipping message signals")


# ==================== Appointment Signals ====================

def connect_appointment_signals():
    """Connect appointment-related signals if appointment app is available."""
    try:
        from appointment.models import Appointment

        @receiver(post_save, sender=Appointment)
        def notify_on_appointment(sender, instance, created, **kwargs):
            """Notify users about appointment changes."""
            try:
                if created:
                    # Notify client about booked appointment
                    notification_service.send_notification(
                        recipient=instance.client,
                        notification_type='appointment_booked',
                        title='Appointment Confirmed',
                        message=f'Your appointment for {instance.service.name} has been confirmed',
                        channels=['email', 'sms', 'in_app'],
                        action_url=f'/appointments/{instance.id}/',
                        action_text='View Details',
                        context_data={
                            'service_name': instance.service.name,
                            'appointment_date': instance.appointment_datetime.strftime('%B %d, %Y'),
                            'appointment_time': instance.appointment_datetime.strftime('%I:%M %p'),
                            'duration': str(instance.duration) if hasattr(instance, 'duration') else 'N/A',
                            'location': instance.location if hasattr(instance, 'location') else 'TBD',
                        },
                        content_object=instance,
                        priority='high',
                    )

                    # Notify provider about new booking
                    if hasattr(instance, 'provider') and instance.provider:
                        notification_service.send_notification(
                            recipient=instance.provider.user,
                            notification_type='appointment_booked',
                            title='New Appointment Booking',
                            message=f'New appointment booked for {instance.service.name}',
                            sender=instance.client,
                            channels=['email', 'in_app', 'push'],
                            action_url=f'/appointments/{instance.id}/',
                            action_text='View Details',
                            content_object=instance,
                            priority='high',
                        )

                else:
                    # Check for status changes
                    if instance.status == 'cancelled':
                        notification_service.send_notification(
                            recipient=instance.client,
                            notification_type='appointment_cancelled',
                            title='Appointment Cancelled',
                            message=f'Your appointment for {instance.service.name} has been cancelled',
                            channels=['email', 'sms', 'in_app'],
                            action_url='/appointments/',
                            action_text='Reschedule',
                            content_object=instance,
                            priority='high',
                        )

            except Exception as e:
                logger.error(f"Failed to send appointment notification: {e}")

    except ImportError:
        logger.debug("Appointment app not available, skipping appointment signals")


# ==================== ATS/Recruitment Signals ====================

def connect_ats_signals():
    """Connect ATS-related signals for recruitment notifications."""
    try:
        from ats.models import Application, Interview, Offer

        @receiver(post_save, sender=Application)
        def notify_on_application(sender, instance, created, **kwargs):
            """Notify hiring team when a new application is submitted."""
            if created:
                try:
                    # Notify hiring manager and recruiter about new application
                    recipients = []
                    if instance.job.hiring_manager:
                        recipients.append(instance.job.hiring_manager)
                    if instance.job.recruiter and instance.job.recruiter != instance.job.hiring_manager:
                        recipients.append(instance.job.recruiter)

                    for recipient in recipients:
                        notification_service.send_notification(
                            recipient=recipient,
                            notification_type='application_received',
                            title='New Application Received',
                            message=f'{instance.candidate.full_name} applied for {instance.job.title}',
                            channels=['email', 'in_app', 'push'],
                            action_url=f'/ats/applications/{instance.id}/',
                            action_text='View Application',
                            context_data={
                                'candidate_name': instance.candidate.full_name,
                                'job_title': instance.job.title,
                                'candidate_email': instance.candidate.email,
                                'source': instance.candidate.source or 'Direct',
                            },
                            content_object=instance,
                            priority='normal',
                        )
                except Exception as e:
                    logger.error(f"Failed to send application notification: {e}")

        @receiver(pre_save, sender=Application)
        def track_application_stage_change(sender, instance, **kwargs):
            """Track stage changes for notification purposes."""
            if instance.pk:
                try:
                    old_instance = Application.objects.get(pk=instance.pk)
                    instance._old_stage = old_instance.current_stage
                    instance._old_status = old_instance.status
                except Application.DoesNotExist:
                    instance._old_stage = None
                    instance._old_status = None
            else:
                instance._old_stage = None
                instance._old_status = None

        @receiver(post_save, sender=Application)
        def notify_on_application_status_change(sender, instance, created, **kwargs):
            """Notify candidate when their application status changes."""
            if not created and hasattr(instance, '_old_status'):
                old_status = instance._old_status
                new_status = instance.status

                # Notify on rejection
                if old_status != 'rejected' and new_status == 'rejected':
                    try:
                        # Only notify if candidate has a linked user account
                        if hasattr(instance.candidate, 'user') and instance.candidate.user:
                            notification_service.send_notification(
                                recipient=instance.candidate.user,
                                notification_type='application_rejected',
                                title='Application Update',
                                message=f'Your application for {instance.job.title} has been reviewed.',
                                channels=['email', 'in_app'],
                                action_url=f'/careers/',
                                action_text='Browse Jobs',
                                context_data={
                                    'job_title': instance.job.title,
                                },
                                content_object=instance,
                                priority='normal',
                            )
                    except Exception as e:
                        logger.error(f"Failed to send rejection notification: {e}")

        @receiver(post_save, sender=Interview)
        def notify_on_interview_scheduled(sender, instance, created, **kwargs):
            """Notify candidate when interview is scheduled."""
            if created and instance.status == 'scheduled':
                try:
                    # Notify candidate if they have a user account
                    candidate = instance.application.candidate
                    if hasattr(candidate, 'user') and candidate.user:
                        notification_service.send_notification(
                            recipient=candidate.user,
                            notification_type='interview_scheduled',
                            title='Interview Scheduled',
                            message=f'Your interview for {instance.application.job.title} has been scheduled',
                            channels=['email', 'sms', 'in_app', 'push'],
                            action_url=f'/applications/{instance.application.id}/',
                            action_text='View Details',
                            context_data={
                                'job_title': instance.application.job.title,
                                'interview_type': instance.interview_type,
                                'scheduled_date': instance.scheduled_start.strftime('%B %d, %Y') if instance.scheduled_start else 'TBD',
                                'scheduled_time': instance.scheduled_start.strftime('%I:%M %p') if instance.scheduled_start else 'TBD',
                                'location': instance.location or 'Virtual',
                                'meeting_url': instance.meeting_url or '',
                            },
                            content_object=instance,
                            priority='high',
                        )

                    # Notify interviewers
                    if hasattr(instance, 'interviewers'):
                        for interviewer in instance.interviewers.all():
                            notification_service.send_notification(
                                recipient=interviewer,
                                notification_type='interview_assigned',
                                title='Interview Assignment',
                                message=f'You have been assigned to interview {candidate.full_name}',
                                channels=['email', 'in_app', 'push'],
                                action_url=f'/ats/interviews/{instance.id}/',
                                action_text='View Interview',
                                context_data={
                                    'candidate_name': candidate.full_name,
                                    'job_title': instance.application.job.title,
                                    'scheduled_date': instance.scheduled_start.strftime('%B %d, %Y') if instance.scheduled_start else 'TBD',
                                    'scheduled_time': instance.scheduled_start.strftime('%I:%M %p') if instance.scheduled_start else 'TBD',
                                },
                                content_object=instance,
                                priority='high',
                            )
                except Exception as e:
                    logger.error(f"Failed to send interview notification: {e}")

        @receiver(post_save, sender=Offer)
        def notify_on_offer(sender, instance, created, **kwargs):
            """Notify relevant parties about offer status changes."""
            try:
                candidate = instance.application.candidate

                if created:
                    # New offer created - notify hiring manager for review
                    if instance.application.job.hiring_manager:
                        notification_service.send_notification(
                            recipient=instance.application.job.hiring_manager,
                            notification_type='offer_created',
                            title='Offer Draft Created',
                            message=f'An offer for {candidate.full_name} is ready for review',
                            channels=['email', 'in_app'],
                            action_url=f'/ats/offers/{instance.id}/',
                            action_text='Review Offer',
                            context_data={
                                'candidate_name': candidate.full_name,
                                'job_title': instance.job_title,
                                'base_salary': str(instance.base_salary),
                            },
                            content_object=instance,
                            priority='high',
                        )

                elif instance.status == 'sent':
                    # Offer sent to candidate
                    if hasattr(candidate, 'user') and candidate.user:
                        notification_service.send_notification(
                            recipient=candidate.user,
                            notification_type='offer_sent',
                            title='Job Offer Received!',
                            message=f'Congratulations! You have received an offer for {instance.job_title}',
                            channels=['email', 'sms', 'in_app', 'push'],
                            action_url=f'/offers/{instance.id}/',
                            action_text='View Offer',
                            context_data={
                                'job_title': instance.job_title,
                                'start_date': instance.start_date.strftime('%B %d, %Y') if instance.start_date else 'TBD',
                                'expiration_date': instance.expiration_date.strftime('%B %d, %Y') if instance.expiration_date else 'TBD',
                            },
                            content_object=instance,
                            priority='high',
                        )

                elif instance.status == 'accepted':
                    # Offer accepted - notify hiring team
                    recipients = []
                    if instance.application.job.hiring_manager:
                        recipients.append(instance.application.job.hiring_manager)
                    if instance.application.job.recruiter:
                        recipients.append(instance.application.job.recruiter)

                    for recipient in recipients:
                        notification_service.send_notification(
                            recipient=recipient,
                            notification_type='offer_accepted',
                            title='Offer Accepted!',
                            message=f'{candidate.full_name} has accepted the offer for {instance.job_title}',
                            channels=['email', 'in_app', 'push'],
                            action_url=f'/ats/offers/{instance.id}/',
                            action_text='View Offer',
                            context_data={
                                'candidate_name': candidate.full_name,
                                'job_title': instance.job_title,
                                'start_date': instance.start_date.strftime('%B %d, %Y') if instance.start_date else 'TBD',
                            },
                            content_object=instance,
                            priority='high',
                        )

                elif instance.status == 'declined':
                    # Offer declined - notify hiring team
                    if instance.application.job.hiring_manager:
                        notification_service.send_notification(
                            recipient=instance.application.job.hiring_manager,
                            notification_type='offer_declined',
                            title='Offer Declined',
                            message=f'{candidate.full_name} has declined the offer for {instance.job_title}',
                            channels=['email', 'in_app'],
                            action_url=f'/ats/applications/{instance.application.id}/',
                            action_text='View Application',
                            context_data={
                                'candidate_name': candidate.full_name,
                                'job_title': instance.job_title,
                            },
                            content_object=instance,
                            priority='normal',
                        )

            except Exception as e:
                logger.error(f"Failed to send offer notification: {e}")

    except ImportError:
        logger.debug("ATS app not available, skipping ATS signals")


# ==================== Dispute Signals ====================

def connect_dispute_signals():
    """Connect dispute-related signals if services app is available."""
    try:
        from services.models import ServiceDispute

        @receiver(post_save, sender=ServiceDispute)
        def notify_on_dispute(sender, instance, created, **kwargs):
            """Notify parties about dispute status."""
            try:
                if created:
                    # Notify the other party about new dispute
                    if instance.filed_by == instance.contract.client:
                        recipient = instance.contract.provider.user
                    else:
                        recipient = instance.contract.client

                    notification_service.send_notification(
                        recipient=recipient,
                        notification_type='dispute_filed',
                        title='Dispute Filed',
                        message=f'A dispute has been filed for contract "{instance.contract.title}"',
                        channels=['email', 'in_app', 'push'],
                        action_url=f'/services/disputes/{instance.id}/',
                        action_text='View Dispute',
                        context_data={
                            'contract_title': instance.contract.title or 'Service Contract',
                            'dispute_reason': instance.reason[:100] if instance.reason else '',
                        },
                        content_object=instance,
                        priority='high',
                    )
                else:
                    # Notify both parties on status change
                    if instance.status == 'resolved':
                        for recipient in [instance.contract.client, instance.contract.provider.user]:
                            notification_service.send_notification(
                                recipient=recipient,
                                notification_type='dispute_resolved',
                                title='Dispute Resolved',
                                message=f'The dispute for "{instance.contract.title}" has been resolved',
                                channels=['email', 'in_app'],
                                action_url=f'/services/disputes/{instance.id}/',
                                action_text='View Resolution',
                                content_object=instance,
                                priority='normal',
                            )
            except Exception as e:
                logger.error(f"Failed to send dispute notification: {e}")

    except ImportError:
        logger.debug("Services app not available, skipping dispute signals")


# ==================== Connect All Signals ====================

def connect_all_signals():
    """Connect all notification signals from various apps."""
    connect_proposal_signals()
    connect_contract_signals()
    connect_review_signals()
    connect_payment_signals()
    connect_message_signals()
    connect_appointment_signals()
    connect_ats_signals()
    connect_dispute_signals()


# Auto-connect signals when this module is imported
connect_all_signals()
