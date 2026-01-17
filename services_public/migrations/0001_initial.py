# Generated manually for services_public initial migration

from django.db import migrations, models
import django.contrib.gis.db.models as gis_models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='PublicServiceCatalog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('provider_uuid', models.UUIDField(db_index=True, unique=True)),
                ('tenant_id', models.IntegerField(db_index=True)),
                ('tenant_schema_name', models.CharField(db_index=True, max_length=100)),
                ('provider_name', models.CharField(db_index=True, max_length=255)),
                ('provider_avatar_url', models.URLField(blank=True)),
                ('bio', models.TextField(blank=True)),
                ('tagline', models.CharField(blank=True, max_length=255)),
                ('provider_type', models.CharField(blank=True, db_index=True, max_length=100)),
                ('location_city', models.CharField(blank=True, db_index=True, max_length=100)),
                ('location_state', models.CharField(blank=True, max_length=100)),
                ('location_country', models.CharField(blank=True, max_length=100)),
                ('location', gis_models.PointField(blank=True, geography=True, null=True, srid=4326)),
                ('can_work_remotely', models.BooleanField(db_index=True, default=False)),
                ('can_work_onsite', models.BooleanField(default=False)),
                ('hourly_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('minimum_budget', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('category_names', models.JSONField(default=list)),
                ('category_slugs', models.JSONField(db_index=True, default=list)),
                ('skills_data', models.JSONField(default=list)),
                ('rating_avg', models.DecimalField(blank=True, db_index=True, decimal_places=2, max_digits=3, null=True)),
                ('total_reviews', models.IntegerField(db_index=True, default=0)),
                ('completed_jobs_count', models.IntegerField(default=0)),
                ('response_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=5, null=True)),
                ('avg_response_time_hours', models.DecimalField(blank=True, decimal_places=2, max_digits=8, null=True)),
                ('availability_status', models.CharField(db_index=True, default='available', max_length=50)),
                ('is_verified', models.BooleanField(db_index=True, default=False)),
                ('is_featured', models.BooleanField(db_index=True, default=False)),
                ('is_accepting_projects', models.BooleanField(db_index=True, default=True)),
                ('published_at', models.DateTimeField(db_index=True)),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('booking_url', models.URLField()),
            ],
            options={
                'db_table': 'services_public_catalog',
                'ordering': ['-published_at'],
                'indexes': [
                    models.Index(fields=['provider_name'], name='svc_pub_name_idx'),
                    models.Index(fields=['provider_type'], name='svc_pub_type_idx'),
                    models.Index(fields=['location_city'], name='svc_pub_location_idx'),
                    models.Index(fields=['can_work_remotely'], name='svc_pub_remote_idx'),
                    models.Index(fields=['rating_avg'], name='svc_pub_rating_idx'),
                    models.Index(fields=['total_reviews'], name='svc_pub_reviews_idx'),
                    models.Index(fields=['is_verified'], name='svc_pub_verified_idx'),
                    models.Index(fields=['is_featured'], name='svc_pub_featured_idx'),
                    models.Index(fields=['availability_status'], name='svc_pub_avail_idx'),
                    models.Index(fields=['published_at'], name='svc_pub_published_idx'),
                ],
            },
        ),
    ]
