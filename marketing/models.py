from django.db import models
from django.utils import timezone

# Create your models here.

class VisitEvent(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    marketing_id = models.CharField(max_length=32, db_index=True)
    ip_address = models.GenericIPAddressField()
    country = models.CharField(max_length=2, db_index=True)
    device_type = models.CharField(max_length=32)
    browser = models.CharField(max_length=32)
    os = models.CharField(max_length=32)
    path = models.CharField(max_length=256)
    method = models.CharField(max_length=8)
    utm_source = models.CharField(max_length=128, blank=True, null=True)
    utm_medium = models.CharField(max_length=128, blank=True, null=True)
    utm_campaign = models.CharField(max_length=128, blank=True, null=True)
    utm_content = models.CharField(max_length=128, blank=True, null=True)
    utm_term = models.CharField(max_length=128, blank=True, null=True)
    ref = models.CharField(max_length=128, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['marketing_id']),
            models.Index(fields=['country']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['device_type']),
        ]
        ordering = ['-timestamp']

class AggregatedStats(models.Model):
    date = models.DateField(db_index=True)
    country = models.CharField(max_length=2, db_index=True)
    device_type = models.CharField(max_length=32)
    total_visits = models.IntegerField(default=0)
    # Expand with additional statistics as needed

    class Meta:
        unique_together = ('date', 'country', 'device_type')
        ordering = ['-date']

# Prospects or Leads capturing basic contact info and status
class Prospect(models.Model):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=128, blank=True)
    last_name = models.CharField(max_length=128, blank=True)
    company = models.CharField(max_length=256, blank=True)
    phone = models.CharField(max_length=32, blank=True)
    source = models.CharField(max_length=256, blank=True, help_text='Lead source or campaign')
    added_on = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=32, default='new', choices=[
        ('new', 'New'),
        ('contacted', 'Contacted'),
        ('qualified', 'Qualified'),
        ('converted', 'Converted'),
        ('disqualified', 'Disqualified'),
    ])

# Newsletter campaigns and scheduling
class NewsletterCampaign(models.Model):
    title = models.CharField(max_length=256)
    subject = models.CharField(max_length=256)
    content = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)
    scheduled_for = models.DateTimeField(blank=True, null=True)
    sent = models.BooleanField(default=False)
    sent_on = models.DateTimeField(blank=True, null=True)

# Tracking newsletter subscribers (contacts)
class NewsletterSubscriber(models.Model):
    email = models.EmailField(unique=True)
    subscribed_on = models.DateTimeField(auto_now_add=True)
    unsubscribed_on = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField(default=True)

# Link subscriber to campaigns and track open/click stats
class NewsletterTracking(models.Model):
    subscriber = models.ForeignKey(NewsletterSubscriber, on_delete=models.CASCADE)
    campaign = models.ForeignKey(NewsletterCampaign, on_delete=models.CASCADE)
    opened = models.BooleanField(default=False)
    opened_on = models.DateTimeField(blank=True, null=True)
    clicked = models.BooleanField(default=False)
    clicked_on = models.DateTimeField(blank=True, null=True)

# Marketing conversions (e.g., purchase, signup)
class ConversionEvent(models.Model):
    marketing_id = models.CharField(max_length=32, db_index=True)
    event_name = models.CharField(max_length=128)  # E.g., 'purchase', 'signup'
    value = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    metadata = models.JSONField(blank=True, null=True)  # Store additional info (product ID, campaign etc.)

