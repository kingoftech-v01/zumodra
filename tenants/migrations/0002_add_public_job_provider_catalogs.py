# Generated manually for bidirectional tenant-to-public sync
# Phase 2: Job sync implementation

from django.db import migrations, models
import django.db.models.deletion
import django.contrib.postgres.fields
import django.contrib.gis.db.models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PublicJobCatalog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True, verbose_name='UUID')),
                ('job_uuid', models.UUIDField(db_index=True, verbose_name='Original Job UUID')),
                ('tenant_schema_name', models.CharField(db_index=True, max_length=63, verbose_name='Tenant Schema')),

                # Job Information
                ('title', models.CharField(db_index=True, max_length=255, verbose_name='Job Title')),
                ('slug', models.SlugField(blank=True, max_length=255, verbose_name='URL Slug')),
                ('reference_code', models.CharField(blank=True, max_length=50, verbose_name='Reference Code')),

                # Category (denormalized)
                ('category_name', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Category Name')),
                ('category_slug', models.SlugField(blank=True, db_index=True, max_length=100, verbose_name='Category Slug')),

                # Job Type & Level
                ('job_type', models.CharField(
                    blank=True,
                    choices=[
                        ('full_time', 'Full-time'),
                        ('part_time', 'Part-time'),
                        ('contract', 'Contract'),
                        ('temporary', 'Temporary'),
                        ('internship', 'Internship'),
                        ('freelance', 'Freelance'),
                    ],
                    db_index=True,
                    max_length=20,
                    verbose_name='Job Type'
                )),
                ('experience_level', models.CharField(
                    blank=True,
                    choices=[
                        ('entry', 'Entry Level'),
                        ('intermediate', 'Intermediate'),
                        ('senior', 'Senior'),
                        ('lead', 'Lead'),
                        ('executive', 'Executive'),
                    ],
                    db_index=True,
                    max_length=20,
                    verbose_name='Experience Level'
                )),
                ('remote_policy', models.CharField(
                    blank=True,
                    choices=[
                        ('on_site', 'On-site'),
                        ('remote', 'Remote'),
                        ('hybrid', 'Hybrid'),
                        ('flexible', 'Flexible'),
                    ],
                    db_index=True,
                    max_length=20,
                    verbose_name='Remote Policy'
                )),

                # Location
                ('location_city', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='City')),
                ('location_state', models.CharField(blank=True, max_length=100, verbose_name='State/Province')),
                ('location_country', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Country')),
                ('location_coordinates', django.contrib.gis.db.models.PointField(blank=True, null=True, srid=4326, verbose_name='Location Coordinates')),

                # Description Fields (sanitized HTML)
                ('description', models.TextField(blank=True, verbose_name='Job Description')),
                ('responsibilities', models.TextField(blank=True, verbose_name='Responsibilities')),
                ('requirements', models.TextField(blank=True, verbose_name='Requirements')),
                ('benefits', models.TextField(blank=True, verbose_name='Benefits')),

                # Salary (conditional - only if show_salary=True)
                ('salary_min', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True, verbose_name='Minimum Salary')),
                ('salary_max', models.DecimalField(blank=True, decimal_places=2, max_digits=12, null=True, verbose_name='Maximum Salary')),
                ('salary_currency', models.CharField(blank=True, default='USD', max_length=3, verbose_name='Salary Currency')),
                ('salary_period', models.CharField(
                    blank=True,
                    choices=[
                        ('hourly', 'Per Hour'),
                        ('daily', 'Per Day'),
                        ('weekly', 'Per Week'),
                        ('monthly', 'Per Month'),
                        ('yearly', 'Per Year'),
                    ],
                    default='yearly',
                    max_length=20,
                    verbose_name='Salary Period'
                )),
                ('show_salary', models.BooleanField(default=False, verbose_name='Show Salary Publicly')),

                # Skills (JSONField for flexibility)
                ('required_skills', models.JSONField(blank=True, default=list, verbose_name='Required Skills')),
                ('preferred_skills', models.JSONField(blank=True, default=list, verbose_name='Preferred Skills')),

                # Additional Info
                ('positions_count', models.PositiveIntegerField(default=1, verbose_name='Number of Positions')),
                ('team', models.CharField(blank=True, max_length=100, verbose_name='Team/Department')),

                # Company Info (denormalized from tenant)
                ('company_name', models.CharField(db_index=True, max_length=255, verbose_name='Company Name')),
                ('company_logo_url', models.URLField(blank=True, max_length=500, verbose_name='Company Logo URL')),

                # Metadata
                ('is_featured', models.BooleanField(db_index=True, default=False, verbose_name='Featured Job')),
                ('application_deadline', models.DateField(blank=True, null=True, verbose_name='Application Deadline')),
                ('published_at', models.DateTimeField(db_index=True, verbose_name='Published Date')),
                ('synced_at', models.DateTimeField(auto_now=True, verbose_name='Last Synced')),

                # SEO Fields
                ('meta_title', models.CharField(blank=True, max_length=255, verbose_name='Meta Title')),
                ('meta_description', models.TextField(blank=True, max_length=500, verbose_name='Meta Description')),

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
                'db_table': 'tenants_publicjobcatalog',
                'indexes': [
                    models.Index(fields=['tenant', 'is_featured'], name='tenants_pub_tenant_featured_idx'),
                    models.Index(fields=['job_type', 'experience_level'], name='tenants_pub_job_type_exp_idx'),
                    models.Index(fields=['location_country', 'location_city'], name='tenants_pub_location_idx'),
                    models.Index(fields=['-published_at'], name='tenants_pub_published_idx'),
                    models.Index(fields=['category_slug'], name='tenants_pub_category_idx'),
                    models.Index(fields=['remote_policy'], name='tenants_pub_remote_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='PublicProviderCatalog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True, verbose_name='UUID')),
                ('provider_uuid', models.UUIDField(db_index=True, verbose_name='Original Provider UUID')),
                ('tenant_schema_name', models.CharField(db_index=True, max_length=63, verbose_name='Tenant Schema')),

                # Provider Profile
                ('display_name', models.CharField(db_index=True, max_length=255, verbose_name='Display Name')),
                ('provider_type', models.CharField(
                    blank=True,
                    choices=[
                        ('individual', 'Individual Freelancer'),
                        ('company', 'Company'),
                        ('agency', 'Agency'),
                    ],
                    default='individual',
                    max_length=20,
                    verbose_name='Provider Type'
                )),
                ('bio', models.TextField(blank=True, verbose_name='Biography')),
                ('tagline', models.CharField(blank=True, max_length=255, verbose_name='Tagline')),

                # Media
                ('avatar_url', models.URLField(blank=True, max_length=500, verbose_name='Avatar URL')),
                ('cover_image_url', models.URLField(blank=True, max_length=500, verbose_name='Cover Image URL')),

                # Location
                ('city', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='City')),
                ('state', models.CharField(blank=True, max_length=100, verbose_name='State/Province')),
                ('country', models.CharField(blank=True, db_index=True, max_length=100, verbose_name='Country')),
                ('location', django.contrib.gis.db.models.PointField(blank=True, null=True, srid=4326, verbose_name='Location Coordinates')),

                # Categories & Skills (denormalized as JSON arrays)
                ('category_names', models.JSONField(blank=True, default=list, verbose_name='Category Names')),
                ('category_slugs', models.JSONField(blank=True, default=list, verbose_name='Category Slugs')),
                ('skills_data', models.JSONField(
                    blank=True,
                    default=list,
                    help_text='Array of {name, level, years_experience}',
                    verbose_name='Skills Data'
                )),

                # Pricing
                ('hourly_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Hourly Rate')),
                ('minimum_budget', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True, verbose_name='Minimum Budget')),
                ('currency', models.CharField(blank=True, default='USD', max_length=3, verbose_name='Currency')),

                # Statistics
                ('rating_avg', models.DecimalField(blank=True, db_index=True, decimal_places=2, max_digits=3, null=True, verbose_name='Average Rating')),
                ('total_reviews', models.PositiveIntegerField(default=0, verbose_name='Total Reviews')),
                ('completed_jobs_count', models.PositiveIntegerField(default=0, verbose_name='Completed Jobs')),
                ('response_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=5, null=True, verbose_name='Response Rate %')),
                ('avg_response_time_hours', models.PositiveIntegerField(blank=True, null=True, verbose_name='Avg Response Time (hours)')),

                # Availability & Status
                ('availability_status', models.CharField(
                    blank=True,
                    choices=[
                        ('available', 'Available Now'),
                        ('busy', 'Busy'),
                        ('unavailable', 'Unavailable'),
                    ],
                    default='available',
                    max_length=20,
                    verbose_name='Availability Status'
                )),
                ('is_verified', models.BooleanField(db_index=True, default=False, verbose_name='Verified Provider')),
                ('is_featured', models.BooleanField(db_index=True, default=False, verbose_name='Featured Provider')),
                ('is_accepting_projects', models.BooleanField(default=True, verbose_name='Accepting Projects')),

                # Work Preferences
                ('can_work_remotely', models.BooleanField(default=True, verbose_name='Can Work Remotely')),
                ('can_work_onsite', models.BooleanField(default=False, verbose_name='Can Work On-site')),

                # Sync Metadata
                ('published_at', models.DateTimeField(db_index=True, verbose_name='Published Date')),
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
                'db_table': 'tenants_publicprovidercatalog',
                'indexes': [
                    models.Index(fields=['tenant', 'is_featured'], name='tenants_ppc_tenant_featured_idx'),
                    models.Index(fields=['-rating_avg'], name='tenants_ppc_rating_idx'),
                    models.Index(fields=['country', 'city'], name='tenants_ppc_location_idx'),
                    models.Index(fields=['-published_at'], name='tenants_ppc_published_idx'),
                    models.Index(fields=['is_verified'], name='tenants_ppc_verified_idx'),
                ],
            },
        ),
        migrations.AlterUniqueTogether(
            name='publicjobcatalog',
            unique_together={('tenant_schema_name', 'job_uuid')},
        ),
        migrations.AlterUniqueTogether(
            name='publicprovidercatalog',
            unique_together={('tenant_schema_name', 'provider_uuid')},
        ),
    ]
