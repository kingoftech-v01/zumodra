# Generated manually for TenantProfile model

import django.db.models.deletion
import phonenumber_field.modelfields
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_initial'),
        ('configurations', '0001_initial'),
        ('tenants', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TenantProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, unique=True)),
                ('employee_id', models.CharField(blank=True, help_text='Company employee ID number', max_length=50)),
                ('job_title', models.CharField(max_length=100)),
                ('hire_date', models.DateField(blank=True, null=True)),
                ('employment_type', models.CharField(
                    choices=[
                        ('full_time', 'Full Time'),
                        ('part_time', 'Part Time'),
                        ('contract', 'Contract'),
                        ('temporary', 'Temporary'),
                        ('intern', 'Intern/Co-op'),
                        ('freelance', 'Freelance')
                    ],
                    default='full_time',
                    max_length=20
                )),
                ('address_line1', models.CharField(blank=True, max_length=255)),
                ('address_line2', models.CharField(blank=True, max_length=255)),
                ('postal_code', models.CharField(blank=True, max_length=20)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('emergency_contact_name', models.CharField(blank=True, max_length=100)),
                ('emergency_contact_phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=128, null=True, region=None)),

                # Synced fields from PublicProfile
                ('full_name', models.CharField(blank=True, help_text='Synced from PublicProfile.display_name', max_length=100)),
                ('avatar_url', models.URLField(blank=True, help_text='Synced from PublicProfile.avatar (ImageField → URL)')),
                ('professional_title', models.CharField(blank=True, help_text='Synced from PublicProfile.professional_title', max_length=100)),
                ('bio', models.TextField(blank=True, help_text='Synced from PublicProfile.bio')),
                ('phone', models.CharField(blank=True, help_text='Synced from PublicProfile.phone', max_length=20)),
                ('email_work', models.EmailField(blank=True, help_text='Synced from PublicProfile.email', max_length=254)),
                ('linkedin_url', models.URLField(blank=True, help_text='Synced from PublicProfile.linkedin_url')),
                ('github_url', models.URLField(blank=True, help_text='Synced from PublicProfile.github_url')),
                ('portfolio_url', models.URLField(blank=True, help_text='Synced from PublicProfile.portfolio_url')),
                ('city', models.CharField(blank=True, help_text='Synced from PublicProfile.city', max_length=100)),
                ('state', models.CharField(blank=True, help_text='Synced from PublicProfile.state', max_length=100)),
                ('country', models.CharField(blank=True, help_text='Synced from PublicProfile.country', max_length=2)),
                ('skills', models.TextField(blank=True, help_text='Synced from PublicProfile.skills (JSON → text)')),
                ('cv_file_url', models.URLField(blank=True, help_text='Synced from PublicProfile.cv_file (FileField → URL)')),
                ('cv_last_updated', models.DateTimeField(blank=True, help_text='Synced from PublicProfile.cv_last_updated', null=True)),

                # Metadata
                ('last_synced_at', models.DateTimeField(blank=True, help_text='Last time data was synced from PublicProfile', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),

                # Foreign Keys
                ('department', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='profiles',
                    to='configurations.department'
                )),
                ('reports_to', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='subordinate_profiles',
                    to='accounts.tenantuser'
                )),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='profiles',
                    to='tenants.tenant'
                )),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='tenant_profiles',
                    to=settings.AUTH_USER_MODEL
                )),
            ],
            options={
                'verbose_name': 'Tenant Profile',
                'verbose_name_plural': 'Tenant Profiles',
                'db_table': 'accounts_tenantprofile',
                'ordering': ['full_name'],
            },
        ),
        migrations.AddIndex(
            model_name='tenantprofile',
            index=models.Index(fields=['user', 'tenant'], name='accounts_te_user_id_tenant_idx'),
        ),
        migrations.AddIndex(
            model_name='tenantprofile',
            index=models.Index(fields=['employee_id'], name='accounts_te_employe_idx'),
        ),
        migrations.AddConstraint(
            model_name='tenantprofile',
            constraint=models.UniqueConstraint(fields=('user', 'tenant'), name='accounts_tenantprofile_unique_user_tenant'),
        ),
    ]
