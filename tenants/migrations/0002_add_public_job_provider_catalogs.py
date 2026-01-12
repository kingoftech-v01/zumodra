# Generated manually for bidirectional sync system
# Adds PublicJobCatalog and PublicProviderCatalog to public schema

import django.contrib.gis.db.models
import django.db.models.deletion
from decimal import Decimal
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PublicJobCatalog',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('uuid', models.UUIDField(db_index=True, unique=True, verbose_name='Job UUID')),
                ('job_uuid', models.UUIDField(db_index=True, verbose_name='Original Job UUID')),
                ('tenant_schema_name', models.CharField(max_length=63, verbose_name='Tenant Schema')),

                # Job Details
                ('title', models.CharField(db_index=True, max_length=255, verbose_name='Job Title')),
                ('slug', models.SlugField(blank=True, max_length=255, verbose_name='URL Slug')),
                ('reference_code', models.CharField(blank=True, max_length=50, verbose_name='Reference Code')),
                ('category_name', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Category Name')),
                ('category_slug', models.SlugField(blank=True, max_length=100, verbose_name='Category Slug')),

                # Job Type & Requirements
                ('job_type', models.CharField(db_index=True, max_length=20, verbose_name='Job Type')),
                ('experience_level', models.CharField(blank=True, max_length=20, verbose_name='Experience Level')),
                ('remote_policy', models.CharField(blank=True, db_index=True, max_length=20, verbose_name='Remote Policy')),

                # Location
                ('location_city', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='City')),
                ('location_state', models.CharField(blank=True, max_length=100, verbose_name='State/Province')),
                ('location_country', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Country')),
                ('location_coordinates', django.contrib.gis.db.models.PointField(blank=True, null=True, srid=4326, verbose_name='Location Coordinates')),

                # Job Description (HTML sanitized)
                ('description', models.TextField(blank=True, verbose_name='Job Description')),
                ('responsibilities', models.TextField(blank=True, verbose_name='Responsibilities')),
                ('requirements', models.TextField(blank=True, verbose_name='Requirements')),
                ('benefits', models.TextField(blank=True, verbose_name='Benefits')),

                # Compensation
                ('salary_min', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Minimum Salary')),
                ('salary_max', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Maximum Salary')),
                ('currency', models.CharField(default='CAD', max_length=3, verbose_name='Currency')),

                # Skills (JSON arrays)
                ('required_skills', models.JSONField(blank=True, default=list, verbose_name='Required Skills')),
                ('preferred_skills', models.JSONField(blank=True, default=list, verbose_name='Preferred Skills')),

                # Team & Organization
                ('positions_count', models.PositiveSmallIntegerField(default=1, verbose_name='Number of Positions')),
                ('team', models.CharField(blank=True, max_length=100, verbose_name='Team/Department')),

                # Company Info (denormalized)
                ('company_name', models.CharField(db_index=True, max_length=255, verbose_name='Company Name')),
                ('company_logo_url', models.CharField(blank=True, max_length=500, verbose_name='Company Logo URL')),

                # Status
                ('is_featured', models.BooleanField(db_index=True, default=False, verbose_name='Featured Job')),

                # Sync Metadata
                ('published_at', models.DateTimeField(db_index=True, verbose_name='Published Date')),
                ('synced_at', models.DateTimeField(auto_now=True, verbose_name='Last Synced')),

                # Foreign Key
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='published_jobs',
                    to='tenants.tenant',
                    verbose_name='Tenant'
                )),
            ],
            options={
                'verbose_name': 'Public Job Catalog',
                'verbose_name_plural': 'Public Job Catalog',
                'ordering': ['-is_featured', '-published_at'],
            },
        ),
        migrations.CreateModel(
            name='PublicProviderCatalog',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('uuid', models.UUIDField(db_index=True, unique=True, verbose_name='Provider UUID')),
                ('provider_uuid', models.UUIDField(db_index=True, verbose_name='Original Provider UUID')),
                ('tenant_schema_name', models.CharField(max_length=63, verbose_name='Tenant Schema')),

                # Profile Information
                ('display_name', models.CharField(db_index=True, max_length=255, verbose_name='Display Name')),
                ('provider_type', models.CharField(db_index=True, max_length=20, verbose_name='Provider Type')),
                ('bio', models.TextField(blank=True, max_length=2000, verbose_name='Bio')),
                ('tagline', models.CharField(blank=True, max_length=200, verbose_name='Tagline')),

                # Media URLs
                ('avatar_url', models.CharField(blank=True, max_length=500, verbose_name='Avatar URL')),
                ('cover_image_url', models.CharField(blank=True, max_length=500, verbose_name='Cover Image URL')),

                # Location
                ('city', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='City')),
                ('state', models.CharField(blank=True, max_length=100, verbose_name='State/Province')),
                ('country', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Country')),
                ('location', django.contrib.gis.db.models.PointField(blank=True, null=True, srid=4326, verbose_name='Location Coordinates')),

                # Categories & Skills (JSON)
                ('category_names', models.JSONField(blank=True, default=list, verbose_name='Category Names')),
                ('category_slugs', models.JSONField(blank=True, default=list, verbose_name='Category Slugs')),
                ('skills_data', models.JSONField(blank=True, default=list, verbose_name='Skills Data')),

                # Pricing
                ('hourly_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Hourly Rate')),
                ('minimum_budget', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Minimum Budget')),
                ('currency', models.CharField(default='CAD', max_length=3, verbose_name='Currency')),

                # Stats & Reputation
                ('rating_avg', models.DecimalField(db_index=True, decimal_places=2, default=Decimal('0.00'), max_digits=3, verbose_name='Average Rating')),
                ('total_reviews', models.PositiveIntegerField(default=0, verbose_name='Total Reviews')),
                ('completed_jobs_count', models.PositiveIntegerField(default=0, verbose_name='Completed Jobs')),
                ('response_rate', models.PositiveSmallIntegerField(default=0, verbose_name='Response Rate')),
                ('avg_response_time_hours', models.PositiveSmallIntegerField(default=0, verbose_name='Average Response Time')),

                # Availability & Status
                ('availability_status', models.CharField(db_index=True, default='available', max_length=20, verbose_name='Availability Status')),
                ('is_verified', models.BooleanField(db_index=True, default=False, verbose_name='Verified Provider')),
                ('is_featured', models.BooleanField(db_index=True, default=False, verbose_name='Featured Provider')),
                ('is_accepting_projects', models.BooleanField(db_index=True, default=True, verbose_name='Accepting Projects')),

                # Work Preferences
                ('can_work_remotely', models.BooleanField(default=True, verbose_name='Can Work Remotely')),
                ('can_work_onsite', models.BooleanField(default=False, verbose_name='Can Work On-site')),

                # Sync Metadata
                ('published_at', models.DateTimeField(auto_now_add=True, verbose_name='Published Date')),
                ('synced_at', models.DateTimeField(auto_now=True, verbose_name='Last Synced')),

                # Foreign Key
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='published_providers',
                    to='tenants.tenant',
                    verbose_name='Tenant'
                )),
            ],
            options={
                'verbose_name': 'Public Provider Catalog',
                'verbose_name_plural': 'Public Provider Catalog',
                'ordering': ['-is_featured', '-rating_avg', '-published_at'],
            },
        ),

        # Add indexes for PublicJobCatalog
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['tenant', 'is_featured'], name='jcat_ten_featured'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['job_type', 'remote_policy'], name='jcat_type_remote'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['location_country', 'location_city'], name='jcat_location'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['category_slug'], name='jcat_category'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['tenant_schema_name', 'job_uuid'], name='jcat_sync_ref'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['-published_at'], name='jcat_published'),
        ),

        # Add indexes for PublicProviderCatalog
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['tenant', 'is_verified'], name='pcat_ten_verified'),
        ),
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['provider_type', 'is_accepting_projects'], name='pcat_type_accept'),
        ),
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['country', 'city'], name='pcat_location'),
        ),
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['tenant_schema_name', 'provider_uuid'], name='pcat_sync_ref'),
        ),
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['-rating_avg', '-total_reviews'], name='pcat_rating'),
        ),
        migrations.AddIndex(
            model_name='publicprovidercatalog',
            index=models.Index(fields=['availability_status'], name='pcat_availability'),
        ),

        # Add unique constraints
        migrations.AddConstraint(
            model_name='publicjobcatalog',
            constraint=models.UniqueConstraint(
                fields=['tenant_schema_name', 'job_uuid'],
                name='unique_job_per_tenant_schema'
            ),
        ),
        migrations.AddConstraint(
            model_name='publicprovidercatalog',
            constraint=models.UniqueConstraint(
                fields=['tenant_schema_name', 'provider_uuid'],
                name='unique_provider_per_tenant_schema'
            ),
        ),
    ]
