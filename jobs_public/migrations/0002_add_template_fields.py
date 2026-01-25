# Generated manually - Add template fields to PublicJobCatalog model
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jobs_public', '0001_initial'),
    ]

    operations = [
        # Job Overview fields
        migrations.AddField(
            model_name='publicjobcatalog',
            name='experience_level',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='Experience level (entry, mid, senior, etc.)',
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='hours_per_week',
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text='Expected hours per week',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='years_of_experience',
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text='Required years of experience',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='english_level',
            field=models.CharField(
                blank=True,
                help_text='Required English proficiency (basic, conversational, fluent, native)',
                max_length=50,
            ),
        ),

        # Rich Content fields (JSON lists)
        migrations.AddField(
            model_name='publicjobcatalog',
            name='responsibilities_list',
            field=models.JSONField(
                default=list,
                help_text='List of job responsibilities (bullet points)',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='requirements_list',
            field=models.JSONField(
                default=list,
                help_text='List of job requirements (bullet points)',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='qualifications_list',
            field=models.JSONField(
                default=list,
                help_text='List of preferred qualifications (bullet points)',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='benefits_list',
            field=models.JSONField(
                default=list,
                help_text='List of benefits (bullet points)',
            ),
        ),

        # Media fields
        migrations.AddField(
            model_name='publicjobcatalog',
            name='image_gallery',
            field=models.JSONField(
                default=list,
                help_text='List of image URLs for job gallery',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='video_url',
            field=models.URLField(
                blank=True,
                help_text='Promotional video URL (YouTube, Vimeo, etc.)',
            ),
        ),

        # Geocoding fields
        migrations.AddField(
            model_name='publicjobcatalog',
            name='latitude',
            field=models.FloatField(
                blank=True,
                db_index=True,
                help_text='Latitude coordinate for map display',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='longitude',
            field=models.FloatField(
                blank=True,
                db_index=True,
                help_text='Longitude coordinate for map display',
                null=True,
            ),
        ),

        # Metadata fields
        migrations.AddField(
            model_name='publicjobcatalog',
            name='expiration_date',
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                help_text='Application deadline',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='view_count',
            field=models.PositiveIntegerField(
                db_index=True,
                default=0,
                help_text='Number of times job has been viewed',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='application_count',
            field=models.PositiveIntegerField(
                db_index=True,
                default=0,
                help_text='Number of applications received',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='is_active',
            field=models.BooleanField(
                db_index=True,
                default=True,
                help_text='Whether job is currently active',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='is_expired',
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text='Whether job has expired',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='is_featured',
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text='Whether job is featured',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='salary_period',
            field=models.CharField(
                default='yearly',
                help_text='Salary payment period (hourly, daily, weekly, monthly, yearly)',
                max_length=35,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='show_salary',
            field=models.BooleanField(
                default=False,
                help_text='Whether salary is publicly visible',
            ),
        ),

        # Company Information fields (denormalized from Tenant)
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_rating',
            field=models.DecimalField(
                blank=True,
                decimal_places=2,
                help_text='Company rating (1.00-5.00)',
                max_digits=3,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_established_date',
            field=models.DateField(
                blank=True,
                help_text='Company founding date',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_industry',
            field=models.CharField(
                blank=True,
                help_text='Company industry',
                max_length=100,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_size',
            field=models.CharField(
                blank=True,
                help_text='Company size (employee count range)',
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_website',
            field=models.URLField(
                blank=True,
                help_text='Company website URL',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_linkedin',
            field=models.URLField(
                blank=True,
                help_text='Company LinkedIn URL',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_twitter',
            field=models.URLField(
                blank=True,
                help_text='Company Twitter/X URL',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_facebook',
            field=models.URLField(
                blank=True,
                help_text='Company Facebook URL',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_instagram',
            field=models.URLField(
                blank=True,
                help_text='Company Instagram URL',
            ),
        ),
        migrations.AddField(
            model_name='publicjobcatalog',
            name='company_pinterest',
            field=models.URLField(
                blank=True,
                help_text='Company Pinterest URL',
            ),
        ),

        # Add new indexes
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['latitude', 'longitude'], name='ats_pub_geo_idx'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['experience_level'], name='ats_pub_exp_idx'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['-view_count'], name='ats_pub_views_idx'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['expiration_date'], name='ats_pub_expiry_idx'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['is_active', 'is_expired'], name='ats_pub_active_idx'),
        ),
        migrations.AddIndex(
            model_name='publicjobcatalog',
            index=models.Index(fields=['is_featured', '-published_at'], name='ats_pub_featured_idx'),
        ),
    ]
