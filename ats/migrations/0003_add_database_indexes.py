# Generated migration for adding database indexes to ATS models
# Improves query performance for frequently accessed fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ats', '0002_add_background_checks'),
    ]

    operations = [
        # JobPosting indexes
        migrations.AlterField(
            model_name='jobposting',
            name='status',
            field=models.CharField(
                max_length=35,
                choices=[
                    ('draft', 'Draft'),
                    ('open', 'Open'),
                    ('closed', 'Closed'),
                    ('archived', 'Archived'),
                ],
                default='draft',
                db_index=True,
                help_text='Job posting status'
            ),
        ),
        migrations.AlterField(
            model_name='jobposting',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
            ),
        ),
        migrations.AlterField(
            model_name='jobposting',
            name='published_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
            ),
        ),

        # Application indexes
        migrations.AlterField(
            model_name='application',
            name='status',
            field=models.CharField(
                max_length=35,
                choices=[
                    ('new', 'New'),
                    ('in_review', 'In Review'),
                    ('phone_screen', 'Phone Screen'),
                    ('assessment', 'Assessment'),
                    ('interviewing', 'Interviewing'),
                    ('background_check_pending', 'Background Check Pending'),
                    ('background_check_in_progress', 'Background Check In Progress'),
                    ('background_check_cleared', 'Background Check Cleared'),
                    ('background_check_failed', 'Background Check Failed'),
                    ('offer_pending', 'Offer Pending'),
                    ('offer_extended', 'Offer Extended'),
                    ('offer_accepted', 'Offer Accepted'),
                    ('offer_declined', 'Offer Declined'),
                    ('hired', 'Hired'),
                    ('rejected', 'Rejected'),
                    ('withdrawn', 'Withdrawn'),
                    ('on_hold', 'On Hold'),
                ],
                default='new',
                db_index=True,
                help_text='Application status in pipeline'
            ),
        ),

        # Interview indexes
        migrations.AlterField(
            model_name='interview',
            name='status',
            field=models.CharField(
                max_length=35,
                choices=[
                    ('scheduled', 'Scheduled'),
                    ('confirmed', 'Confirmed'),
                    ('completed', 'Completed'),
                    ('rescheduled', 'Rescheduled'),
                    ('cancelled', 'Cancelled'),
                    ('no_show', 'No Show'),
                ],
                default='scheduled',
                db_index=True,
                help_text='Interview status'
            ),
        ),
        migrations.AlterField(
            model_name='interview',
            name='scheduled_start',
            field=models.DateTimeField(
                db_index=True,
                help_text='When the interview is scheduled to start'
            ),
        ),
    ]
