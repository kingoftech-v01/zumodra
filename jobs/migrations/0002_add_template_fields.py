# Generated manually - Add template fields to JobPosting and create JobImage model
from django.core.validators import FileExtensionValidator, MaxValueValidator
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('jobs', '0001_initial'),
    ]

    operations = [
        # Add fields to JobPosting model
        migrations.AddField(
            model_name='jobposting',
            name='hours_per_week',
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text='Expected hours per week',
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='jobposting',
            name='years_of_experience',
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text='Required years of experience',
                null=True,
                validators=[MaxValueValidator(50)],
            ),
        ),
        migrations.AddField(
            model_name='jobposting',
            name='english_level',
            field=models.CharField(
                blank=True,
                choices=[
                    ('basic', 'Basic'),
                    ('conversational', 'Conversational'),
                    ('fluent', 'Fluent'),
                    ('native', 'Native/Bilingual'),
                ],
                help_text='Required English proficiency level',
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name='jobposting',
            name='video_url',
            field=models.URLField(
                blank=True,
                help_text='URL to job promotional video (YouTube, Vimeo, etc.)',
            ),
        ),

        # Create JobImage model
        migrations.CreateModel(
            name='JobImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(
                    help_text='Job image file (JPG, PNG, or WebP)',
                    upload_to='jobs/images/%Y/%m/',
                    validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp'])],
                )),
                ('caption', models.CharField(
                    blank=True,
                    help_text='Optional image caption describing the photo',
                    max_length=200,
                )),
                ('order', models.PositiveSmallIntegerField(
                    default=0,
                    help_text='Display order (0 = first, higher numbers appear later)',
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('job', models.ForeignKey(
                    help_text='Job posting this image belongs to',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='images',
                    to='jobs.jobposting',
                )),
            ],
            options={
                'verbose_name': 'Job Image',
                'verbose_name_plural': 'Job Images',
                'ordering': ['order', 'created_at'],
            },
        ),

        # Add index to JobImage
        migrations.AddIndex(
            model_name='jobimage',
            index=models.Index(fields=['job', 'order'], name='ats_jobimage_job_order'),
        ),
    ]
