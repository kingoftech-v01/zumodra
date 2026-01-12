# Generated manually for browse pages redo with WebSocket

from django.db import migrations, models
import django.contrib.gis.db.models as gis_models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0003_alter_publicjobcatalog_options_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='location_coordinates',
            field=gis_models.PointField(
                srid=4326,
                null=True,
                blank=True,
                help_text='Geographic coordinates for map display (lon, lat)'
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='geocode_attempted',
            field=models.BooleanField(
                default=False,
                help_text='Whether geocoding has been attempted for this address'
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='geocode_error',
            field=models.CharField(
                max_length=255,
                blank=True,
                default='',
                help_text='Error message if geocoding failed'
            ),
        ),
    ]
