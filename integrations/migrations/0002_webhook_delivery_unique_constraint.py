# Generated migration to add unique constraint on webhook delivery

from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0001_initial'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='webhookdelivery',
            constraint=models.UniqueConstraint(
                condition=~Q(('event_id', '')),
                fields=('endpoint', 'event_id'),
                name='unique_webhook_delivery_per_endpoint'
            ),
        ),
        migrations.AlterField(
            model_name='webhookdelivery',
            name='event_id',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='External event ID for deduplication',
                max_length=255
            ),
        ),
    ]
