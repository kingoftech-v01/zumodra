# Generated manually for waitlist system
# Date: 2026-01-24

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('core_identity', '0001_initial'),
    ]

    operations = [
        # Add waitlist fields to CustomUser
        migrations.AddField(
            model_name='customuser',
            name='is_waitlisted',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='User is on waitlist and cannot access platform yet'
            ),
        ),
        migrations.AddField(
            model_name='customuser',
            name='waitlist_joined_at',
            field=models.DateTimeField(
                blank=True,
                null=True,
                help_text='When user joined waitlist'
            ),
        ),
        migrations.AddField(
            model_name='customuser',
            name='waitlist_position',
            field=models.PositiveIntegerField(
                blank=True,
                db_index=True,
                null=True,
                help_text='Position in waitlist (for gamification)'
            ),
        ),

        # Add indexes for waitlist fields
        migrations.AddIndex(
            model_name='customuser',
            index=models.Index(fields=['is_waitlisted'], name='core_ident_is_wait_idx'),
        ),
        migrations.AddIndex(
            model_name='customuser',
            index=models.Index(fields=['waitlist_position'], name='core_ident_waitlis_idx'),
        ),

        # Create PlatformLaunch model
        migrations.CreateModel(
            name='PlatformLaunch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('launch_date', models.DateTimeField(
                    blank=True,
                    db_index=True,
                    null=True,
                    help_text='When platform becomes publicly accessible'
                )),
                ('is_launched', models.BooleanField(
                    default=False,
                    db_index=True,
                    help_text='Manual override to launch immediately'
                )),
                ('waitlist_enabled', models.BooleanField(
                    default=True,
                    db_index=True,
                    help_text='Enable waitlist system'
                )),
                ('waitlist_message', models.TextField(
                    default='Thank you for your interest! The platform will launch soon.',
                    help_text='Message shown to waitlisted users'
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Platform Launch Configuration',
                'verbose_name_plural': 'Platform Launch Configuration',
                'db_table': 'core_identity_platformlaunch',
            },
        ),
    ]
