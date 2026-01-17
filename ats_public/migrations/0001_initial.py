# Generated manually for ats_public initial migration

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='PublicJobCatalog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('jobposting_uuid', models.UUIDField(db_index=True, unique=True)),
                ('tenant_id', models.IntegerField(db_index=True)),
                ('tenant_schema_name', models.CharField(db_index=True, max_length=100)),
                ('company_name', models.CharField(db_index=True, max_length=255)),
                ('company_logo_url', models.URLField(blank=True)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('description_html', models.TextField()),
                ('employment_type', models.CharField(blank=True, db_index=True, max_length=50)),
                ('location_city', models.CharField(blank=True, db_index=True, max_length=100)),
                ('location_state', models.CharField(blank=True, max_length=100)),
                ('location_country', models.CharField(blank=True, max_length=100)),
                ('is_remote', models.BooleanField(db_index=True, default=False)),
                ('salary_min', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('salary_max', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True)),
                ('salary_currency', models.CharField(default='USD', max_length=3)),
                ('category_names', models.JSONField(default=list)),
                ('category_slugs', models.JSONField(db_index=True, default=list)),
                ('required_skills', models.JSONField(default=list)),
                ('published_at', models.DateTimeField(db_index=True)),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('application_url', models.URLField()),
            ],
            options={
                'db_table': 'ats_public_job_catalog',
                'ordering': ['-published_at'],
                'indexes': [
                    models.Index(fields=['title'], name='ats_pub_title_idx'),
                    models.Index(fields=['location_city'], name='ats_pub_location_idx'),
                    models.Index(fields=['employment_type'], name='ats_pub_emp_type_idx'),
                    models.Index(fields=['is_remote'], name='ats_pub_remote_idx'),
                    models.Index(fields=['published_at'], name='ats_pub_published_idx'),
                    models.Index(fields=['company_name'], name='ats_pub_company_idx'),
                ],
            },
        ),
    ]
