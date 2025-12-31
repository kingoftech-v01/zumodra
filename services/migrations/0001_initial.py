# Generated migration for services app consolidation
# This migration creates all models with their canonical names

from decimal import Decimal
import uuid
from django.conf import settings
import django.contrib.gis.db.models.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('configurations', '0001_initial'),
    ]

    operations = [
        # ServiceCategory
        migrations.CreateModel(
            name='ServiceCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('name', models.CharField(max_length=100, verbose_name='Category Name')),
                ('slug', models.SlugField(max_length=120, unique=True)),
                ('description', models.TextField(blank=True)),
                ('icon', models.CharField(blank=True, max_length=50)),
                ('image', models.ImageField(blank=True, null=True, upload_to='categories/')),
                ('sort_order', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='subcategories', to='services.servicecategory')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service Category',
                'verbose_name_plural': 'Service Categories',
                'ordering': ['sort_order', 'name'],
            },
        ),

        # ServiceTag
        migrations.CreateModel(
            name='ServiceTag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('name', models.CharField(max_length=50, verbose_name='Tag Name')),
                ('slug', models.SlugField(max_length=60, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Service Tag',
                'verbose_name_plural': 'Service Tags',
                'ordering': ['name'],
            },
        ),

        # ServiceImage
        migrations.CreateModel(
            name='ServiceImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('image', models.ImageField(upload_to='services/images/')),
                ('alt_text', models.CharField(blank=True, max_length=200)),
                ('description', models.CharField(blank=True, max_length=255)),
                ('sort_order', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Service Image',
                'verbose_name_plural': 'Service Images',
                'ordering': ['sort_order'],
            },
        ),

        # ServiceProvider
        migrations.CreateModel(
            name='ServiceProvider',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='service_provider_profile', to=settings.AUTH_USER_MODEL)),
                ('company', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='service_providers', to='configurations.company')),
                ('provider_type', models.CharField(choices=[('individual', 'Individual'), ('agency', 'Agency'), ('company', 'Company')], default='individual', max_length=20)),
                ('display_name', models.CharField(blank=True, max_length=150)),
                ('bio', models.TextField(blank=True)),
                ('tagline', models.CharField(blank=True, max_length=200)),
                ('avatar', models.ImageField(blank=True, null=True, upload_to='providers/avatars/')),
                ('cover_image', models.ImageField(blank=True, null=True, upload_to='providers/covers/')),
                ('address', models.CharField(blank=True, max_length=255)),
                ('city', models.CharField(blank=True, max_length=100)),
                ('state', models.CharField(blank=True, max_length=100)),
                ('postal_code', models.CharField(blank=True, max_length=20)),
                ('country', models.CharField(blank=True, max_length=100)),
                ('location', django.contrib.gis.db.models.fields.PointField(blank=True, null=True, srid=4326)),
                ('location_lat', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True)),
                ('location_lng', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True)),
                ('hourly_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('minimum_budget', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('rating_avg', models.DecimalField(decimal_places=2, default=Decimal('0.00'), max_digits=3)),
                ('total_reviews', models.PositiveIntegerField(default=0)),
                ('completed_jobs_count', models.PositiveIntegerField(default=0)),
                ('total_earnings', models.DecimalField(decimal_places=2, default=Decimal('0.00'), max_digits=12)),
                ('response_rate', models.DecimalField(decimal_places=2, default=Decimal('0.00'), max_digits=5)),
                ('availability_status', models.CharField(choices=[('available', 'Available'), ('busy', 'Busy'), ('away', 'Away'), ('offline', 'Offline')], default='available', max_length=20)),
                ('is_verified', models.BooleanField(default=False)),
                ('is_featured', models.BooleanField(default=False)),
                ('is_private', models.BooleanField(default=False)),
                ('is_mobile', models.BooleanField(default=False)),
                ('is_accepting_projects', models.BooleanField(default=True)),
                ('stripe_account_id', models.CharField(blank=True, max_length=255)),
                ('stripe_onboarding_complete', models.BooleanField(default=False)),
                ('stripe_payouts_enabled', models.BooleanField(default=False)),
                ('categories', models.ManyToManyField(blank=True, related_name='providers', to='services.servicecategory')),
                ('last_active_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service Provider',
                'verbose_name_plural': 'Service Providers',
                'ordering': ['-rating_avg', '-completed_jobs_count'],
            },
        ),

        # ProviderSkill
        migrations.CreateModel(
            name='ProviderSkill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='provider_skills', to='services.serviceprovider')),
                ('skill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='provider_skills', to='configurations.skill')),
                ('level', models.CharField(choices=[('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('advanced', 'Advanced'), ('expert', 'Expert')], default='intermediate', max_length=20)),
                ('years_experience', models.PositiveSmallIntegerField(default=0)),
                ('is_verified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Provider Skill',
                'verbose_name_plural': 'Provider Skills',
                'unique_together': {('provider', 'skill')},
            },
        ),

        # Service
        migrations.CreateModel(
            name='Service',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='services', to='services.serviceprovider')),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='services', to='services.servicecategory')),
                ('name', models.CharField(max_length=200)),
                ('slug', models.SlugField(blank=True, max_length=220, unique=True)),
                ('description', models.TextField(blank=True)),
                ('short_description', models.CharField(blank=True, max_length=300)),
                ('service_type', models.CharField(choices=[('fixed', 'Fixed Price'), ('hourly', 'Hourly Rate'), ('quote', 'Request Quote')], default='fixed', max_length=20)),
                ('price', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('price_min', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('price_max', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('delivery_type', models.CharField(choices=[('online', 'Online/Remote'), ('onsite', 'On-site'), ('both', 'Both')], default='online', max_length=20)),
                ('duration_days', models.PositiveIntegerField(blank=True, null=True)),
                ('revisions_included', models.PositiveSmallIntegerField(default=1)),
                ('thumbnail', models.ImageField(blank=True, null=True, upload_to='services/thumbnails/')),
                ('video_url', models.URLField(blank=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_featured', models.BooleanField(default=False)),
                ('view_count', models.PositiveIntegerField(default=0)),
                ('order_count', models.PositiveIntegerField(default=0)),
                ('tags', models.ManyToManyField(blank=True, related_name='services', to='services.servicetag')),
                ('images', models.ManyToManyField(blank=True, related_name='services', to='services.serviceimage')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service',
                'verbose_name_plural': 'Services',
                'ordering': ['-created_at'],
            },
        ),

        # ServiceLike
        migrations.CreateModel(
            name='ServiceLike',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_likes', to=settings.AUTH_USER_MODEL)),
                ('service', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='likes', to='services.service')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Service Like',
                'verbose_name_plural': 'Service Likes',
                'unique_together': {('user', 'service')},
            },
        ),

        # ClientRequest
        migrations.CreateModel(
            name='ClientRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_requests', to=settings.AUTH_USER_MODEL)),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='client_requests', to='services.servicecategory')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('budget_min', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('budget_max', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('deadline', models.DateField(blank=True, null=True)),
                ('location', django.contrib.gis.db.models.fields.PointField(blank=True, null=True, srid=4326)),
                ('location_address', models.CharField(blank=True, max_length=255)),
                ('remote_allowed', models.BooleanField(default=True)),
                ('status', models.CharField(choices=[('open', 'Open'), ('in_progress', 'In Progress'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='open', max_length=20)),
                ('required_skills', models.ManyToManyField(blank=True, related_name='client_requests', to='configurations.skill')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Client Request',
                'verbose_name_plural': 'Client Requests',
                'ordering': ['-created_at'],
            },
        ),

        # ProviderMatch
        migrations.CreateModel(
            name='ProviderMatch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('client_request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='matches', to='services.clientrequest')),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='matches', to='services.serviceprovider')),
                ('score', models.DecimalField(decimal_places=2, default=Decimal('0.00'), max_digits=5)),
                ('match_reasons', models.JSONField(blank=True, default=dict)),
                ('viewed_by_client', models.BooleanField(default=False)),
                ('accepted_by_client', models.BooleanField(default=False)),
                ('rejected_by_client', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Provider Match',
                'verbose_name_plural': 'Provider Matches',
                'ordering': ['-score'],
                'unique_together': {('client_request', 'provider')},
            },
        ),

        # ServiceProposal
        migrations.CreateModel(
            name='ServiceProposal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('client_request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='proposals', to='services.clientrequest')),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='proposals', to='services.serviceprovider')),
                ('cover_letter', models.TextField(blank=True)),
                ('proposed_rate', models.DecimalField(decimal_places=2, max_digits=10)),
                ('rate_type', models.CharField(choices=[('fixed', 'Fixed'), ('hourly', 'Hourly')], default='fixed', max_length=10)),
                ('estimated_duration', models.CharField(blank=True, max_length=100)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected'), ('withdrawn', 'Withdrawn')], default='pending', max_length=20)),
                ('attachments', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service Proposal',
                'verbose_name_plural': 'Service Proposals',
                'ordering': ['-created_at'],
                'unique_together': {('client_request', 'provider')},
            },
        ),

        # ServiceContract
        migrations.CreateModel(
            name='ServiceContract',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='client_contracts', to=settings.AUTH_USER_MODEL)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='contracts', to='services.serviceprovider')),
                ('proposal', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='contract', to='services.serviceproposal')),
                ('service', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='contracts', to='services.service')),
                ('client_request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='contracts', to='services.clientrequest')),
                ('title', models.CharField(blank=True, max_length=200)),
                ('description', models.TextField(blank=True)),
                ('agreed_rate', models.DecimalField(decimal_places=2, max_digits=10)),
                ('rate_type', models.CharField(choices=[('fixed', 'Fixed'), ('hourly', 'Hourly')], default='fixed', max_length=10)),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('agreed_deadline', models.DateField(blank=True, null=True)),
                ('revisions_allowed', models.PositiveSmallIntegerField(default=1)),
                ('revisions_used', models.PositiveSmallIntegerField(default=0)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('active', 'Active'), ('delivered', 'Delivered'), ('revision', 'In Revision'), ('completed', 'Completed'), ('disputed', 'Disputed'), ('cancelled', 'Cancelled')], default='pending', max_length=20)),
                ('cancellation_reason', models.TextField(blank=True)),
                ('platform_fee_percent', models.DecimalField(decimal_places=2, default=Decimal('10.00'), max_digits=5)),
                ('provider_payout_amount', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('delivered_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('cancelled_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service Contract',
                'verbose_name_plural': 'Service Contracts',
                'ordering': ['-created_at'],
            },
        ),

        # ServiceReview
        migrations.CreateModel(
            name='ServiceReview',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('contract', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='review', to='services.servicecontract')),
                ('reviewer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='given_reviews', to=settings.AUTH_USER_MODEL)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reviews', to='services.serviceprovider')),
                ('rating', models.PositiveSmallIntegerField(choices=[(1, '1 Star'), (2, '2 Stars'), (3, '3 Stars'), (4, '4 Stars'), (5, '5 Stars')])),
                ('content', models.TextField(blank=True)),
                ('communication_rating', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('quality_rating', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('timeliness_rating', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('value_rating', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('provider_response', models.TextField(blank=True)),
                ('provider_response_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Service Review',
                'verbose_name_plural': 'Service Reviews',
                'ordering': ['-created_at'],
            },
        ),

        # ContractMessage
        migrations.CreateModel(
            name='ContractMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tenant_id', models.CharField(db_index=True, max_length=100, verbose_name='Tenant ID')),
                ('contract', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='services.servicecontract')),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='contract_messages_sent', to=settings.AUTH_USER_MODEL)),
                ('content', models.TextField()),
                ('attachments', models.JSONField(blank=True, default=list)),
                ('is_system_message', models.BooleanField(default=False)),
                ('read_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Contract Message',
                'verbose_name_plural': 'Contract Messages',
                'ordering': ['created_at'],
            },
        ),

        # Add escrow_transaction FK to ServiceContract (optional, may need finance app)
        # This will be added in a separate migration once finance app is confirmed
    ]
