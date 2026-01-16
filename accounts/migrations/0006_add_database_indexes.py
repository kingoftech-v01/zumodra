# Generated migration for adding database indexes to Accounts models
# Improves query performance for frequently accessed fields

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_kycverification_document_file'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # TenantUser indexes
        migrations.AlterField(
            model_name='tenantuser',
            name='user',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='tenant_users',
                to=settings.AUTH_USER_MODEL,
                db_index=True,
                help_text='User account'
            ),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='tenant',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='users',
                to='tenants.tenant',
                db_index=True,
                help_text='Tenant organization'
            ),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='role',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pdg', 'PDG'),
                    ('supervisor', 'Supervisor'),
                    ('hr_manager', 'HR Manager'),
                    ('recruiter', 'Recruiter'),
                    ('employee', 'Employee'),
                    ('viewer', 'Viewer'),
                ],
                db_index=True,
                help_text='User role in tenant'
            ),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='is_active',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether this user is active in the tenant'
            ),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='is_primary_tenant',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is the user primary tenant'
            ),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='joined_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the user joined this tenant'
            ),
        ),

        # UserProfile indexes
        migrations.AlterField(
            model_name='userprofile',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the profile was created'
            ),
        ),

        # KYCVerification indexes
        migrations.AlterField(
            model_name='kycverification',
            name='verification_type',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('identity', 'Identity'),
                    ('phone', 'Phone'),
                    ('email', 'Email'),
                    ('address', 'Address'),
                ],
                db_index=True,
                help_text='Type of verification'
            ),
        ),
        migrations.AlterField(
            model_name='kycverification',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pending', 'Pending'),
                    ('verified', 'Verified'),
                    ('rejected', 'Rejected'),
                    ('expired', 'Expired'),
                ],
                default='pending',
                db_index=True,
                help_text='Verification status'
            ),
        ),
        migrations.AlterField(
            model_name='kycverification',
            name='level',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('basic', 'Basic'),
                    ('intermediate', 'Intermediate'),
                    ('advanced', 'Advanced'),
                ],
                default='basic',
                db_index=True,
                help_text='Verification level'
            ),
        ),
        migrations.AlterField(
            model_name='kycverification',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When verification was created'
            ),
        ),

        # ProgressiveConsent indexes
        migrations.AlterField(
            model_name='progressiveconsent',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pending', 'Pending'),
                    ('accepted', 'Accepted'),
                    ('declined', 'Declined'),
                ],
                default='pending',
                db_index=True,
                help_text='Consent status'
            ),
        ),
        migrations.AlterField(
            model_name='progressiveconsent',
            name='requested_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When consent was requested'
            ),
        ),

        # SecurityQuestion indexes
        migrations.AlterField(
            model_name='securityquestion',
            name='user',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='security_questions',
                to=settings.AUTH_USER_MODEL,
                db_index=True,
                help_text='User for this security question'
            ),
        ),
        migrations.AlterField(
            model_name='securityquestion',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the security question was created'
            ),
        ),

        # LoginHistory indexes
        migrations.AlterField(
            model_name='loginhistory',
            name='user',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='login_history',
                to=settings.AUTH_USER_MODEL,
                db_index=True,
                help_text='User who logged in'
            ),
        ),
        migrations.AlterField(
            model_name='loginhistory',
            name='result',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('success', 'Success'),
                    ('failed', 'Failed'),
                    ('blocked', 'Blocked'),
                ],
                db_index=True,
                help_text='Login result'
            ),
        ),
        migrations.AlterField(
            model_name='loginhistory',
            name='ip_address',
            field=models.GenericIPAddressField(
                db_index=True,
                help_text='IP address of login attempt'
            ),
        ),
        migrations.AlterField(
            model_name='loginhistory',
            name='timestamp',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the login attempt occurred'
            ),
        ),

        # TrustScore indexes
        migrations.AlterField(
            model_name='trustscore',
            name='identity_verified',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether identity is verified'
            ),
        ),
        migrations.AlterField(
            model_name='trustscore',
            name='email_verified',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether email is verified'
            ),
        ),

        # EmploymentVerification indexes
        migrations.AlterField(
            model_name='employmentverification',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pending', 'Pending'),
                    ('verified', 'Verified'),
                    ('rejected', 'Rejected'),
                    ('expired', 'Expired'),
                ],
                default='pending',
                db_index=True,
                help_text='Employment verification status'
            ),
        ),
        migrations.AlterField(
            model_name='employmentverification',
            name='token',
            field=models.CharField(
                max_length=255,
                unique=True,
                db_index=True,
                help_text='Verification token'
            ),
        ),
        migrations.AlterField(
            model_name='employmentverification',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When verification was created'
            ),
        ),
        migrations.AlterField(
            model_name='employmentverification',
            name='expires_at',
            field=models.DateTimeField(
                db_index=True,
                help_text='When the verification expires'
            ),
        ),

        # EducationVerification indexes
        migrations.AlterField(
            model_name='educationverification',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pending', 'Pending'),
                    ('verified', 'Verified'),
                    ('rejected', 'Rejected'),
                    ('expired', 'Expired'),
                ],
                default='pending',
                db_index=True,
                help_text='Education verification status'
            ),
        ),
        migrations.AlterField(
            model_name='educationverification',
            name='token',
            field=models.CharField(
                max_length=255,
                unique=True,
                db_index=True,
                help_text='Verification token'
            ),
        ),
        migrations.AlterField(
            model_name='educationverification',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When verification was created'
            ),
        ),
        migrations.AlterField(
            model_name='educationverification',
            name='expires_at',
            field=models.DateTimeField(
                db_index=True,
                help_text='When the verification expires'
            ),
        ),

        # Review indexes
        migrations.AlterField(
            model_name='review',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('pending', 'Pending'),
                    ('published', 'Published'),
                    ('archived', 'Archived'),
                ],
                default='pending',
                db_index=True,
                help_text='Review status'
            ),
        ),
        migrations.AlterField(
            model_name='review',
            name='is_negative',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is a negative review'
            ),
        ),
        migrations.AlterField(
            model_name='review',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the review was created'
            ),
        ),

        # CandidateCV indexes
        migrations.AlterField(
            model_name='candidatecv',
            name='is_primary',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is the primary CV'
            ),
        ),
        migrations.AlterField(
            model_name='candidatecv',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('draft', 'Draft'),
                    ('active', 'Active'),
                    ('archived', 'Archived'),
                ],
                default='draft',
                db_index=True,
                help_text='CV status'
            ),
        ),
        migrations.AlterField(
            model_name='candidatecv',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When CV was created'
            ),
        ),

        # StudentProfile indexes
        migrations.AlterField(
            model_name='studentprofile',
            name='enrollment_status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('active', 'Active'),
                    ('inactive', 'Inactive'),
                    ('graduated', 'Graduated'),
                    ('suspended', 'Suspended'),
                ],
                default='active',
                db_index=True,
                help_text='Student enrollment status'
            ),
        ),
        migrations.AlterField(
            model_name='studentprofile',
            name='enrollment_verified',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether enrollment is verified'
            ),
        ),
        migrations.AlterField(
            model_name='studentprofile',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the student profile was created'
            ),
        ),

        # CoopTerm indexes
        migrations.AlterField(
            model_name='coopterm',
            name='status',
            field=models.CharField(
                max_length=50,
                choices=[
                    ('active', 'Active'),
                    ('completed', 'Completed'),
                    ('cancelled', 'Cancelled'),
                ],
                default='active',
                db_index=True,
                help_text='Coop term status'
            ),
        ),
        migrations.AlterField(
            model_name='coopterm',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the coop term was created'
            ),
        ),
    ]
