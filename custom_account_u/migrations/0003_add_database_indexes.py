# Generated migration for adding database indexes to Custom Account models
# Improves query performance for frequently accessed fields

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('custom_account_u', '0002_publicprofile_profilefieldsync'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # CustomUser indexes
        migrations.AlterField(
            model_name='customuser',
            name='mfa_enabled',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether MFA is enabled for this user'
            ),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='anonymous_mode',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether user operates in anonymous mode'
            ),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='c_u_uuid',
            field=models.CharField(
                max_length=36,
                unique=True,
                db_index=True,
                help_text='Custom user UUID for fast lookups'
            ),
        ),

        # PublicProfile indexes
        migrations.AlterField(
            model_name='publicprofile',
            name='user',
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='public_profile',
                to=settings.AUTH_USER_MODEL,
                db_index=True,
                help_text='User for this public profile'
            ),
        ),
        migrations.AlterField(
            model_name='publicprofile',
            name='available_for_work',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether the user is available for work'
            ),
        ),
        migrations.AlterField(
            model_name='publicprofile',
            name='profile_visibility',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('public', 'Public'),
                    ('private', 'Private'),
                    ('search_only', 'Search Only'),
                    ('verified_only', 'Verified Only'),
                ],
                default='private',
                db_index=True,
                help_text='Profile visibility setting'
            ),
        ),
        migrations.AlterField(
            model_name='publicprofile',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the public profile was created'
            ),
        ),

        # ProfileFieldSync indexes
        migrations.AlterField(
            model_name='profilefieldsync',
            name='user',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='profile_field_syncs',
                to=settings.AUTH_USER_MODEL,
                db_index=True,
                help_text='User for field synchronization'
            ),
        ),
        migrations.AlterField(
            model_name='profilefieldsync',
            name='auto_sync',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether this field is auto-synced'
            ),
        ),
        migrations.AlterField(
            model_name='profilefieldsync',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the sync record was created'
            ),
        ),
    ]
