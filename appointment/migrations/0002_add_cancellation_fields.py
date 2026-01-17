# Generated manually for TODO-APPT-001: Appointment Cancellation Logic
# See appointment/TODO.md for implementation details

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('appointment', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='appointment',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('confirmed', 'Confirmed'),
                    ('completed', 'Completed'),
                    ('cancelled', 'Cancelled'),
                    ('no_show', 'No Show')
                ],
                default='confirmed',
                help_text='Current status of the appointment.',
                max_length=20,
                verbose_name='Status'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='cancelled_at',
            field=models.DateTimeField(
                blank=True,
                help_text='Timestamp when the appointment was cancelled.',
                null=True,
                verbose_name='Cancelled At'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='cancelled_by',
            field=models.ForeignKey(
                blank=True,
                help_text='User who cancelled the appointment.',
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='cancelled_appointments',
                to=settings.AUTH_USER_MODEL,
                verbose_name='Cancelled By'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='cancellation_reason',
            field=models.TextField(
                blank=True,
                help_text='Optional reason provided by user for cancellation.',
                verbose_name='Cancellation Reason'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='refund_amount',
            field=models.DecimalField(
                blank=True,
                decimal_places=2,
                help_text='Amount to be refunded based on cancellation policy.',
                max_digits=10,
                null=True,
                verbose_name='Refund Amount'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='refund_status',
            field=models.CharField(
                choices=[
                    ('none', 'No Refund'),
                    ('pending', 'Refund Pending'),
                    ('processed', 'Refund Processed'),
                    ('failed', 'Refund Failed')
                ],
                default='none',
                help_text='Status of refund processing.',
                max_length=20,
                verbose_name='Refund Status'
            ),
        ),
        migrations.AddField(
            model_name='appointment',
            name='refund_processed_at',
            field=models.DateTimeField(
                blank=True,
                help_text='Timestamp when refund was successfully processed.',
                null=True,
                verbose_name='Refund Processed At'
            ),
        ),
        # Add index for cancelled appointments query performance
        migrations.AddIndex(
            model_name='appointment',
            index=models.Index(fields=['status', '-created_at'], name='appt_status_created_idx'),
        ),
        migrations.AddIndex(
            model_name='appointment',
            index=models.Index(fields=['refund_status'], name='appt_refund_status_idx'),
        ),
    ]
