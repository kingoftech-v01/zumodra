"""
Notification Signals - Auto-create notifications for various events
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse
from services.models import DServiceProposal, DServiceContract, DServiceComment
from .models import Notification


@receiver(post_save, sender=DServiceProposal)
def notify_on_proposal(sender, instance, created, **kwargs):
    """Notify client when a new proposal is submitted"""
    if created:
        # Get client from the request
        client = instance.request.client

        # Check if user wants notifications
        prefs = getattr(client, 'notification_preferences', None)
        if prefs and not prefs.app_on_proposal:
            return

        Notification.objects.create(
            recipient=client,
            sender=instance.provider.user,
            notification_type='proposal',
            title='New Proposal Received',
            message=f'{instance.provider.entity_name} submitted a proposal for your request "{instance.request.title}"',
            content_object=instance,
            action_url=f'/services/request/{instance.request.uuid}/'
        )


@receiver(post_save, sender=DServiceProposal)
def notify_on_proposal_accepted(sender, instance, created, **kwargs):
    """Notify provider when their proposal is accepted"""
    if not created and instance.is_accepted:
        provider = instance.provider.user

        # Check if user wants notifications
        prefs = getattr(provider, 'notification_preferences', None)
        if prefs and not prefs.app_on_proposal:
            return

        Notification.objects.create(
            recipient=provider,
            sender=instance.request.client,
            notification_type='success',
            title='Proposal Accepted!',
            message=f'Your proposal for "{instance.request.title}" has been accepted!',
            content_object=instance,
            action_url=f'/services/contracts/'
        )


@receiver(post_save, sender=DServiceContract)
def notify_on_contract_status_change(sender, instance, created, **kwargs):
    """Notify users when contract status changes"""
    if created:
        # Notify provider about new contract
        provider = instance.provider.user

        prefs = getattr(provider, 'notification_preferences', None)
        if prefs and not prefs.app_on_contract:
            return

        Notification.objects.create(
            recipient=provider,
            sender=instance.client,
            notification_type='contract',
            title='New Contract Created',
            message=f'A new contract has been created for your service',
            content_object=instance,
            action_url=f'/services/contract/{instance.id}/'
        )
    else:
        # Status changed - notify both parties
        if instance.status == 'active':
            # Notify client
            Notification.objects.create(
                recipient=instance.client,
                notification_type='success',
                title='Contract Activated',
                message=f'Your contract with {instance.provider.entity_name} is now active',
                content_object=instance,
                action_url=f'/services/contract/{instance.id}/'
            )

        elif instance.status == 'completed':
            # Notify client
            Notification.objects.create(
                recipient=instance.client,
                notification_type='success',
                title='Contract Completed',
                message=f'Your contract with {instance.provider.entity_name} has been completed',
                content_object=instance,
                action_url=f'/services/contract/{instance.id}/'
            )


@receiver(post_save, sender=DServiceComment)
def notify_on_review(sender, instance, created, **kwargs):
    """Notify provider when they receive a review"""
    if created:
        provider = instance.provider.user

        # Check if user wants notifications
        prefs = getattr(provider, 'notification_preferences', None)
        if prefs and not prefs.app_on_review:
            return

        stars = '⭐' * instance.rating

        Notification.objects.create(
            recipient=provider,
            sender=instance.reviewer,
            notification_type='review',
            title='New Review Received',
            message=f'You received a {instance.rating}-star review: "{instance.content[:100]}"',
            content_object=instance,
            action_url=f'/services/service/{instance.DService.uuid}/'
        )
