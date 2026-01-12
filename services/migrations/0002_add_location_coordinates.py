# Generated manually for browse pages redo with WebSocket

from django.db import migrations, models
import django.contrib.gis.db.models as gis_models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='service',
            name='location_coordinates',
            field=gis_models.PointField(
                srid=4326,
                null=True,
                blank=True,
                help_text='Geographic coordinates for service location (lon, lat)'
            ),
        ),
        migrations.AddField(
            model_name='service',
            name='geocode_attempted',
            field=models.BooleanField(
                default=False,
                help_text='Whether geocoding has been attempted'
            ),
        ),
        migrations.AddField(
            model_name='service',
            name='geocode_error',
            field=models.CharField(
                max_length=255,
                blank=True,
                default='',
                help_text='Error message if geocoding failed'
            ),
        ),
    ]
