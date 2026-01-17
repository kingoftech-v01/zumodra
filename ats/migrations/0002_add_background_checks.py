# Generated manually for background check feature

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ats', '0001_initial'),
        ('tenants', '0005_remove_tenant_geocode_attempted_and_more'),
    ]

    operations = [
        # Update Application model to add new background check statuses
        migrations.AlterField(
            model_name='application',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('new', 'New'),
                    ('in_review', 'In Review'),
                    ('phone_screen', 'Phone Screen'),
                    ('assessment', 'Assessment'),
                    ('interviewing', 'Interviewing'),
                    ('background_check_pending', 'Background Check Pending'),
                    ('background_check_in_progress', 'Background Check In Progress'),
                    ('background_check_cleared', 'Background Check Cleared'),
                    ('background_check_failed', 'Background Check Failed'),
                    ('offer_pending', 'Offer Pending'),
                    ('offer_extended', 'Offer Extended'),
                    ('offer_accepted', 'Offer Accepted'),
                    ('offer_declined', 'Offer Declined'),
                    ('hired', 'Hired'),
                    ('rejected', 'Rejected'),
                    ('withdrawn', 'Withdrawn'),
                    ('on_hold', 'On Hold'),
                ],
                default='new',
            ),
        ),

        # Create BackgroundCheck model
        migrations.CreateModel(
            name='BackgroundCheck',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='tenants.tenant',
                    db_index=True,
                    help_text='Tenant this record belongs to'
                )),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),

                # Provider and package info
                ('provider', models.CharField(
                    max_length=50,
                    choices=[
                        ('checkr', 'Checkr'),
                        ('sterling', 'Sterling'),
                        ('hireright', 'HireRight'),
                    ],
                    help_text='Background check provider'
                )),
                ('package', models.CharField(
                    max_length=100,
                    choices=[
                        ('basic', 'Basic - SSN verification and basic criminal'),
                        ('standard', 'Standard - SSN, criminal, employment'),
                        ('pro', 'Professional - Standard + education + references'),
                        ('comprehensive', 'Comprehensive - All checks + credit + MVR'),
                    ],
                    default='standard',
                    help_text='Background check package level'
                )),

                # External IDs from provider
                ('external_candidate_id', models.CharField(
                    max_length=255,
                    help_text='Candidate ID in provider system',
                    db_index=True
                )),
                ('external_report_id', models.CharField(
                    max_length=255,
                    help_text='Report ID in provider system',
                    db_index=True,
                    unique=True
                )),

                # Status tracking
                ('status', models.CharField(
                    max_length=50,
                    choices=[
                        ('pending', 'Pending'),
                        ('invited', 'Invitation Sent'),
                        ('in_progress', 'In Progress'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                        ('cancelled', 'Cancelled'),
                    ],
                    default='pending',
                    db_index=True
                )),
                ('result', models.CharField(
                    max_length=50,
                    choices=[
                        ('clear', 'Clear'),
                        ('consider', 'Consider'),
                        ('suspended', 'Suspended'),
                    ],
                    blank=True,
                    null=True,
                    db_index=True,
                    help_text='Overall result from provider'
                )),

                # Timestamps
                ('initiated_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True, db_index=True)),

                # Report data
                ('report_url', models.URLField(
                    blank=True,
                    max_length=500,
                    help_text='Link to full report on provider platform'
                )),
                ('report_data', models.JSONField(
                    default=dict,
                    blank=True,
                    help_text='Full report data from provider API'
                )),

                # Consent tracking
                ('consent_given', models.BooleanField(
                    default=False,
                    help_text='Candidate has given consent for background check'
                )),
                ('consent_ip_address', models.GenericIPAddressField(
                    blank=True,
                    null=True,
                    help_text='IP address when consent was given'
                )),
                ('consent_timestamp', models.DateTimeField(
                    blank=True,
                    null=True,
                    help_text='Timestamp when consent was given'
                )),

                # Notes
                ('notes', models.TextField(
                    blank=True,
                    help_text='Internal notes about this background check'
                )),

                # Foreign keys
                ('application', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='background_checks',
                    to='ats.application',
                    help_text='Application this background check is for'
                )),
                ('initiated_by', models.ForeignKey(
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='initiated_background_checks',
                    to=settings.AUTH_USER_MODEL,
                    blank=True,
                    null=True,
                    help_text='User who initiated the background check'
                )),
            ],
            options={
                'verbose_name': 'Background Check',
                'verbose_name_plural': 'Background Checks',
                'ordering': ['-initiated_at'],
                'indexes': [
                    models.Index(fields=['status', 'result'], name='ats_bgcheck_status_result_idx'),
                    models.Index(fields=['provider', 'external_report_id'], name='ats_bgcheck_provider_report_idx'),
                ],
            },
        ),

        # Create BackgroundCheckDocument model
        migrations.CreateModel(
            name='BackgroundCheckDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='tenants.tenant',
                    db_index=True,
                    help_text='Tenant this record belongs to'
                )),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),

                # Document type
                ('document_type', models.CharField(
                    max_length=100,
                    choices=[
                        ('ssn_verification', 'SSN Verification'),
                        ('criminal_search', 'Criminal Record Search'),
                        ('national_criminal', 'National Criminal Database'),
                        ('county_criminal', 'County Criminal Search'),
                        ('federal_criminal', 'Federal Criminal Search'),
                        ('sex_offender', 'Sex Offender Registry'),
                        ('global_watchlist', 'Global Watchlist'),
                        ('employment_verification', 'Employment Verification'),
                        ('education_verification', 'Education Verification'),
                        ('professional_license', 'Professional License Verification'),
                        ('reference_check', 'Reference Check'),
                        ('credit_report', 'Credit Report'),
                        ('motor_vehicle', 'Motor Vehicle Record'),
                        ('civil_court', 'Civil Court Records'),
                        ('eviction_records', 'Eviction Records'),
                    ],
                    db_index=True,
                    help_text='Type of screening/document'
                )),

                # Status and result
                ('status', models.CharField(
                    max_length=50,
                    choices=[
                        ('pending', 'Pending'),
                        ('in_progress', 'In Progress'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                        ('disputed', 'Disputed'),
                    ],
                    default='pending',
                    db_index=True
                )),
                ('result', models.CharField(
                    max_length=50,
                    choices=[
                        ('clear', 'Clear'),
                        ('consider', 'Consider'),
                        ('suspended', 'Suspended'),
                        ('unable_to_complete', 'Unable to Complete'),
                    ],
                    blank=True,
                    null=True,
                    db_index=True
                )),

                # Completion
                ('completed_at', models.DateTimeField(
                    blank=True,
                    null=True,
                    db_index=True
                )),

                # Findings
                ('findings_summary', models.TextField(
                    blank=True,
                    help_text='Summary of findings for this document'
                )),
                ('document_data', models.JSONField(
                    default=dict,
                    blank=True,
                    help_text='Detailed data for this screening from provider'
                )),

                # Foreign key
                ('background_check', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='documents',
                    to='ats.backgroundcheck',
                    help_text='Parent background check'
                )),
            ],
            options={
                'verbose_name': 'Background Check Document',
                'verbose_name_plural': 'Background Check Documents',
                'ordering': ['document_type'],
                'indexes': [
                    models.Index(fields=['document_type', 'status'], name='ats_bgcheck_doc_type_status_idx'),
                ],
            },
        ),

        # Add constraint to ensure one background check per application
        migrations.AddConstraint(
            model_name='backgroundcheck',
            constraint=models.UniqueConstraint(
                fields=['application'],
                name='ats_one_bgcheck_per_application'
            ),
        ),
    ]
