# Generated manually for TODO-CAREERS-001: Add geocoding for company locations
# See careers/TODO.md for implementation details

from django.db import migrations
import django.contrib.gis.db.models as gis_models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0005_remove_tenant_geocode_attempted_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='location',
            field=gis_models.PointField(
                geography=True,
                srid=4326,  # WGS84 (latitude/longitude)
                null=True,
                blank=True,
                help_text='Geographic coordinates for company location'
            ),
        ),
    ]
