# Generated migration for adding database indexes to Services models
# Improves query performance for marketplace operations and filtering

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0002_add_location_coordinates'),
        ('tenants', '__latest__'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Skill indexes
        migrations.AlterField(
            model_name='skill',
            name='level',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('beginner', 'Beginner'),
                    ('intermediate', 'Intermediate'),
                    ('advanced', 'Advanced'),
                    ('expert', 'Expert'),
                ],
                db_index=True,
                help_text='Skill proficiency level'
            ),
        ),
        migrations.AlterField(
            model_name='skill',
            name='is_verified',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether skill is verified'
            ),
        ),

        # ServiceProvider indexes
        migrations.AlterField(
            model_name='serviceprovider',
            name='hourly_rate',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Hourly rate for services'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='minimum_budget',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Minimum project budget'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='currency',
            field=models.CharField(
                max_length=3,
                default='CAD',
                db_index=True,
                help_text='Currency for pricing'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='availability_status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('available', 'Available'),
                    ('busy', 'Busy'),
                    ('unavailable', 'Unavailable'),
                ],
                default='available',
                db_index=True,
                help_text='Current availability status'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='kyc_verified',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether provider is KYC verified'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='is_featured',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether provider is featured in marketplace'
            ),
        ),
        migrations.AlterField(
            model_name='serviceprovider',
            name='is_active',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether provider is active'
            ),
        ),

        # Service indexes
        migrations.AlterField(
            model_name='service',
            name='pricing_model',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('hourly', 'Hourly'),
                    ('fixed', 'Fixed'),
                    ('quote', 'Quote'),
                ],
                db_index=True,
                help_text='Pricing model for service'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='base_price',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Base price for service'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='custom_quote_price',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                null=True,
                blank=True,
                db_index=True,
                help_text='Custom quote price'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='max_price',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Maximum price'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='currency',
            field=models.CharField(
                max_length=3,
                default='CAD',
                db_index=True,
                help_text='Currency for pricing'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='delivery_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('remote', 'Remote'),
                    ('onsite', 'Onsite'),
                    ('hybrid', 'Hybrid'),
                ],
                db_index=True,
                help_text='Service delivery type'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='duration_days',
            field=models.PositiveIntegerField(
                db_index=True,
                help_text='Service duration in days'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='is_active',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether service is active'
            ),
        ),
        migrations.AlterField(
            model_name='service',
            name='is_featured',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether service is featured in marketplace'
            ),
        ),

        # ClientRequest indexes
        migrations.AlterField(
            model_name='clientrequest',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('open', 'Open'),
                    ('in_progress', 'In Progress'),
                    ('closed', 'Closed'),
                    ('cancelled', 'Cancelled'),
                ],
                db_index=True,
                help_text='Request status'
            ),
        ),
        migrations.AlterField(
            model_name='clientrequest',
            name='cross_tenant',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is a cross-tenant request'
            ),
        ),
        migrations.AlterField(
            model_name='clientrequest',
            name='organizational_hiring',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether this is organizational or personal hiring'
            ),
        ),
        migrations.AlterField(
            model_name='clientrequest',
            name='response_deadline',
            field=models.DateTimeField(
                db_index=True,
                help_text='Deadline for provider responses'
            ),
        ),

        # Proposal indexes
        migrations.AlterField(
            model_name='proposal',
            name='proposed_rate',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Proposed rate'
            ),
        ),
        migrations.AlterField(
            model_name='proposal',
            name='rate_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('hourly', 'Hourly'),
                    ('fixed', 'Fixed'),
                    ('project', 'Project'),
                ],
                db_index=True,
                help_text='Type of proposed rate'
            ),
        ),
        migrations.AlterField(
            model_name='proposal',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('pending', 'Pending'),
                    ('accepted', 'Accepted'),
                    ('rejected', 'Rejected'),
                    ('withdrawn', 'Withdrawn'),
                ],
                default='pending',
                db_index=True,
                help_text='Proposal status'
            ),
        ),

        # Contract indexes
        migrations.AlterField(
            model_name='contract',
            name='agreed_rate',
            field=models.DecimalField(
                max_digits=10,
                decimal_places=2,
                db_index=True,
                help_text='Agreed rate for contract'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='rate_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('hourly', 'Hourly'),
                    ('fixed', 'Fixed'),
                    ('project', 'Project'),
                ],
                db_index=True,
                help_text='Type of rate'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='currency',
            field=models.CharField(
                max_length=3,
                default='CAD',
                db_index=True,
                help_text='Currency for contract'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='deadline',
            field=models.DateTimeField(
                db_index=True,
                help_text='Contract deadline'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('draft', 'Draft'),
                    ('active', 'Active'),
                    ('on_hold', 'On Hold'),
                    ('completed', 'Completed'),
                    ('cancelled', 'Cancelled'),
                    ('disputed', 'Disputed'),
                ],
                default='draft',
                db_index=True,
                help_text='Contract status'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='is_active',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether contract is active'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='delivery_date',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When deliverables were provided'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='completed_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When contract was completed'
            ),
        ),
        migrations.AlterField(
            model_name='contract',
            name='cancelled_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When contract was cancelled'
            ),
        ),

        # ContractMessage indexes
        migrations.AlterField(
            model_name='contractmessage',
            name='timestamp',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When message was sent'
            ),
        ),
        migrations.AlterField(
            model_name='contractmessage',
            name='is_system_message',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether this is a system message'
            ),
        ),
        migrations.AlterField(
            model_name='contractmessage',
            name='is_read',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether message has been read'
            ),
        ),
    ]
