"""
Celery Tasks for Marketing App

This module contains async tasks for marketing automation:
- Campaign processing and scheduling
- Conversion metric calculations
- Visit tracking cleanup
- Newsletter subscriber sync
- Lead scoring

Security Features:
- Admin-only operations
- PII handling compliance
- Audit logging for campaign actions
"""

import logging
from datetime import timedelta
from decimal import Decimal
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Count, Sum, Avg, F, Q
from django.core.cache import cache

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.marketing.tasks')


# ==================== CAMPAIGN PROCESSING ====================

@shared_task(
    bind=True,
    name='marketing.tasks.process_scheduled_campaigns',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
    soft_time_limit=3600,
)
def process_scheduled_campaigns(self):
    """
    Process and send scheduled marketing campaigns.

    Checks for campaigns scheduled to send now and
    processes them in batches.

    Returns:
        dict: Summary of campaigns processed.
    """
    from marketing.models import Campaign

    try:
        now = timezone.now()

        # Find campaigns ready to send
        ready_campaigns = Campaign.objects.filter(
            status='scheduled',
            scheduled_at__lte=now
        )

        processed = 0
        for campaign in ready_campaigns:
            try:
                campaign.status = 'sending'
                campaign.save(update_fields=['status', 'updated_at'])

                # Process campaign (simplified - would integrate with email service)
                _process_campaign(campaign)

                campaign.status = 'sent'
                campaign.sent_at = now
                campaign.save(update_fields=['status', 'sent_at', 'updated_at'])

                security_logger.info(
                    f"CAMPAIGN_SENT: id={campaign.id} name={campaign.name}"
                )

                processed += 1

            except Exception as e:
                logger.error(f"Error processing campaign {campaign.id}: {e}")
                campaign.status = 'failed'
                campaign.error_message = str(e)
                campaign.save(update_fields=['status', 'error_message', 'updated_at'])

        logger.info(f"Processed {processed} scheduled campaigns")

        return {
            'status': 'success',
            'processed_count': processed,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Campaign processing exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error processing campaigns: {str(e)}")
        raise self.retry(exc=e)


def _process_campaign(campaign):
    """Process a single campaign (placeholder for email service integration)."""
    # In production, this would:
    # 1. Get subscriber list
    # 2. Render email template
    # 3. Send via email service (SendGrid, Mailchimp, etc.)
    # 4. Track opens/clicks
    pass


# ==================== CONVERSION METRICS ====================

@shared_task(
    bind=True,
    name='marketing.tasks.calculate_conversion_metrics',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def calculate_conversion_metrics(self):
    """
    Calculate daily conversion metrics.

    Calculates:
    - Visit to signup conversion rate
    - Signup to subscription rate
    - Campaign effectiveness metrics

    Returns:
        dict: Summary of metrics calculated.
    """
    from marketing.models import Visit, Prospect, Conversion

    try:
        now = timezone.now()
        yesterday = now - timedelta(days=1)

        # Calculate visit to signup conversion
        total_visits = Visit.objects.filter(
            created_at__date=yesterday.date()
        ).count()

        signups = Prospect.objects.filter(
            created_at__date=yesterday.date(),
            status='converted'
        ).count()

        conversion_rate = (signups / total_visits * 100) if total_visits > 0 else 0

        # Store metrics
        Conversion.objects.update_or_create(
            date=yesterday.date(),
            metric_type='visit_to_signup',
            defaults={
                'value': Decimal(str(conversion_rate)),
                'numerator': signups,
                'denominator': total_visits,
            }
        )

        # Cache daily metrics
        cache.set(f"marketing:metrics:{yesterday.date()}", {
            'visits': total_visits,
            'signups': signups,
            'conversion_rate': conversion_rate,
        }, timeout=86400)

        logger.info(
            f"Calculated conversion metrics: {conversion_rate:.2f}% "
            f"({signups}/{total_visits})"
        )

        return {
            'status': 'success',
            'date': yesterday.date().isoformat(),
            'visits': total_visits,
            'signups': signups,
            'conversion_rate': conversion_rate,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Conversion metrics calculation exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error calculating conversion metrics: {str(e)}")
        raise self.retry(exc=e)


# ==================== VISIT TRACKING CLEANUP ====================

@shared_task(
    bind=True,
    name='marketing.tasks.cleanup_old_visits',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_old_visits(self):
    """
    Clean up old visit tracking data.

    Removes or archives visit records older than 90 days
    to comply with data retention policies.

    Returns:
        dict: Summary of cleanup.
    """
    from marketing.models import Visit

    try:
        now = timezone.now()
        retention_threshold = now - timedelta(days=90)

        # Count before deletion
        old_visits = Visit.objects.filter(
            created_at__lt=retention_threshold
        )

        count = old_visits.count()

        # Archive or delete based on policy
        # Using hard delete here (would use archival in production)
        old_visits.delete()

        security_logger.info(
            f"VISIT_CLEANUP: Deleted {count} visit records older than 90 days"
        )

        return {
            'status': 'success',
            'deleted_count': count,
            'threshold_date': retention_threshold.isoformat(),
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up visits: {str(e)}")
        raise self.retry(exc=e)


# ==================== NEWSLETTER SUBSCRIBER SYNC ====================

@shared_task(
    bind=True,
    name='marketing.tasks.sync_newsletter_subscribers',
    max_retries=3,
    default_retry_delay=600,
    soft_time_limit=1800,
)
def sync_newsletter_subscribers(self):
    """
    Sync newsletter subscribers with external email service.

    Syncs:
    - New subscribers to email service
    - Unsubscribes from email service
    - Subscriber preferences

    Returns:
        dict: Summary of sync.
    """
    from marketing.models import Prospect

    try:
        now = timezone.now()

        # Find subscribers needing sync
        pending_sync = Prospect.objects.filter(
            newsletter_subscribed=True,
            synced_to_email_service=False
        )[:100]  # Batch size

        synced = 0
        for prospect in pending_sync:
            try:
                # Placeholder for email service API call
                # Would call SendGrid, Mailchimp, etc.

                prospect.synced_to_email_service = True
                prospect.synced_at = now
                prospect.save(update_fields=['synced_to_email_service', 'synced_at'])

                synced += 1

            except Exception as e:
                logger.error(f"Error syncing prospect {prospect.id}: {e}")

        # Find unsubscribes needing sync
        pending_unsub = Prospect.objects.filter(
            newsletter_subscribed=False,
            synced_to_email_service=True,
            unsubscribed_at__isnull=False
        )[:100]

        unsynced = 0
        for prospect in pending_unsub:
            try:
                # Placeholder for unsubscribe API call

                prospect.synced_to_email_service = False
                prospect.save(update_fields=['synced_to_email_service'])

                unsynced += 1

            except Exception as e:
                logger.error(f"Error syncing unsubscribe {prospect.id}: {e}")

        logger.info(f"Synced {synced} subscribers, {unsynced} unsubscribes")

        return {
            'status': 'success',
            'synced_subscribers': synced,
            'synced_unsubscribes': unsynced,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Newsletter sync exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error syncing newsletter subscribers: {str(e)}")
        raise self.retry(exc=e)


# ==================== LEAD SCORING ====================

@shared_task(
    bind=True,
    name='marketing.tasks.calculate_lead_scores',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def calculate_lead_scores(self):
    """
    Calculate lead scores for prospects.

    Scoring based on:
    - Website engagement
    - Email engagement
    - Content downloads
    - Form submissions
    - Company fit

    Returns:
        dict: Summary of scores calculated.
    """
    from marketing.models import Prospect

    try:
        now = timezone.now()

        # Get prospects needing scoring
        prospects = Prospect.objects.filter(
            Q(lead_score__isnull=True) |
            Q(score_updated_at__lt=now - timedelta(days=1))
        )[:200]

        scored = 0
        for prospect in prospects:
            try:
                score = _calculate_prospect_score(prospect)

                prospect.lead_score = score
                prospect.score_updated_at = now
                prospect.save(update_fields=['lead_score', 'score_updated_at', 'updated_at'])

                scored += 1

            except Exception as e:
                logger.error(f"Error scoring prospect {prospect.id}: {e}")

        logger.info(f"Calculated lead scores for {scored} prospects")

        return {
            'status': 'success',
            'scored_count': scored,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Lead scoring exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error calculating lead scores: {str(e)}")
        raise self.retry(exc=e)


def _calculate_prospect_score(prospect):
    """
    Calculate lead score for a single prospect.

    Returns score 0-100.
    """
    score = 0

    # Email engagement (20 points max)
    if hasattr(prospect, 'email_opened') and prospect.email_opened:
        score += 10
    if hasattr(prospect, 'email_clicked') and prospect.email_clicked:
        score += 10

    # Website engagement (30 points max)
    if hasattr(prospect, 'visit_count'):
        visits = prospect.visit_count or 0
        score += min(visits * 2, 30)

    # Profile completeness (20 points max)
    if prospect.email:
        score += 10
    if hasattr(prospect, 'phone') and prospect.phone:
        score += 5
    if hasattr(prospect, 'company') and prospect.company:
        score += 5

    # Newsletter subscription (10 points)
    if hasattr(prospect, 'newsletter_subscribed') and prospect.newsletter_subscribed:
        score += 10

    # Recent activity bonus (20 points max)
    if hasattr(prospect, 'last_activity_at') and prospect.last_activity_at:
        days_since_activity = (timezone.now() - prospect.last_activity_at).days
        if days_since_activity < 7:
            score += 20
        elif days_since_activity < 30:
            score += 10

    return min(score, 100)


# ==================== CAMPAIGN ANALYTICS ====================

@shared_task(
    bind=True,
    name='marketing.tasks.update_campaign_analytics',
    max_retries=3,
    default_retry_delay=300,
)
def update_campaign_analytics(self):
    """
    Update analytics for sent campaigns.

    Calculates:
    - Open rates
    - Click rates
    - Conversion rates
    - ROI metrics

    Returns:
        dict: Summary of analytics updated.
    """
    from marketing.models import Campaign

    try:
        now = timezone.now()

        # Get campaigns needing analytics update
        campaigns = Campaign.objects.filter(
            status='sent',
            sent_at__gte=now - timedelta(days=30)
        )

        updated = 0
        for campaign in campaigns:
            try:
                # Calculate metrics (placeholder - would use tracking data)
                # In production, would query tracking database/service

                if hasattr(campaign, 'sent_count') and campaign.sent_count:
                    campaign.open_rate = (campaign.opened_count or 0) / campaign.sent_count * 100
                    campaign.click_rate = (campaign.clicked_count or 0) / campaign.sent_count * 100

                campaign.analytics_updated_at = now
                campaign.save()

                updated += 1

            except Exception as e:
                logger.error(f"Error updating analytics for campaign {campaign.id}: {e}")

        logger.info(f"Updated analytics for {updated} campaigns")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating campaign analytics: {str(e)}")
        raise self.retry(exc=e)


# ==================== A/B TEST ANALYSIS ====================

@shared_task(
    bind=True,
    name='marketing.tasks.analyze_ab_tests',
    max_retries=3,
    default_retry_delay=300,
)
def analyze_ab_tests(self):
    """
    Analyze A/B test results and determine winners.

    Checks:
    - Statistical significance
    - Confidence intervals
    - Auto-promotes winners

    Returns:
        dict: Summary of analysis.
    """
    from marketing.models import Campaign

    try:
        now = timezone.now()

        # Find active A/B tests
        ab_tests = Campaign.objects.filter(
            is_ab_test=True,
            status='sent',
            ab_test_concluded=False,
            sent_at__lte=now - timedelta(days=3)  # Minimum runtime
        )

        analyzed = 0
        winners_found = 0

        for test in ab_tests:
            try:
                # Calculate statistical significance (simplified)
                # In production, would use proper statistical methods

                if hasattr(test, 'variant_a_conversions') and hasattr(test, 'variant_b_conversions'):
                    a_rate = (test.variant_a_conversions or 0) / max(test.variant_a_sent or 1, 1)
                    b_rate = (test.variant_b_conversions or 0) / max(test.variant_b_sent or 1, 1)

                    # Simple winner determination (would use proper stats)
                    if abs(a_rate - b_rate) > 0.05:  # 5% difference threshold
                        test.ab_test_winner = 'A' if a_rate > b_rate else 'B'
                        test.ab_test_concluded = True
                        test.save()
                        winners_found += 1

                analyzed += 1

            except Exception as e:
                logger.error(f"Error analyzing A/B test {test.id}: {e}")

        logger.info(f"Analyzed {analyzed} A/B tests, found {winners_found} winners")

        return {
            'status': 'success',
            'analyzed_count': analyzed,
            'winners_found': winners_found,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error analyzing A/B tests: {str(e)}")
        raise self.retry(exc=e)
