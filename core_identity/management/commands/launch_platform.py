"""
Management command to launch platform and notify waitlisted users.

Usage:
    python manage.py launch_platform
    python manage.py launch_platform --dry-run
    python manage.py launch_platform --no-email
"""

from django.core.management.base import BaseCommand, CommandError
from django.core.mail import send_mass_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone
from django.conf import settings
from core_identity.models import PlatformLaunch, CustomUser
from datetime import datetime


class Command(BaseCommand):
    help = 'Launch platform and notify all waitlisted users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simulate launch without making changes'
        )
        parser.add_argument(
            '--no-email',
            action='store_true',
            help='Skip sending notification emails'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        no_email = options['no_email']

        self.stdout.write('='*70)
        self.stdout.write(self.style.SUCCESS('PLATFORM LAUNCH SCRIPT'))
        self.stdout.write('='*70)

        # Get launch configuration
        launch_config = PlatformLaunch.get_config()

        if launch_config.is_platform_launched:
            self.stdout.write(self.style.WARNING('Platform is already launched!'))
            self.stdout.write(f'Launch date: {launch_config.launch_date}')
            self.stdout.write(f'Manual launch flag: {launch_config.is_launched}')
            return

        # Get all waitlisted users
        waitlisted_users = CustomUser.objects.filter(is_waitlisted=True).order_by('waitlist_position')
        count = waitlisted_users.count()

        self.stdout.write(f'\nFound {count} waitlisted users')

        if count == 0:
            self.stdout.write(self.style.WARNING('No waitlisted users to process'))
            return

        # Show sample of users
        self.stdout.write('\nSample of waitlisted users:')
        for user in waitlisted_users[:5]:
            self.stdout.write(
                f'  - {user.email} (Position: {user.waitlist_position}, Joined: {user.waitlist_joined_at})'
            )
        if count > 5:
            self.stdout.write(f'  ... and {count - 5} more')

        if dry_run:
            self.stdout.write('\n' + self.style.WARNING('DRY RUN - No changes will be made'))
            self.stdout.write('\nActions that would be performed:')
            self.stdout.write(f'  1. Set platform as launched (is_launched=True)')
            self.stdout.write(f'  2. Update {count} users (is_waitlisted=False)')
            if not no_email:
                self.stdout.write(f'  3. Send {count} notification emails')
            else:
                self.stdout.write(f'  3. Skip sending emails (--no-email flag)')
            return

        # Confirm action
        self.stdout.write('\n' + self.style.WARNING('WARNING: This action will:'))
        self.stdout.write(f'  - Launch the platform publicly')
        self.stdout.write(f'  - Grant access to {count} waitlisted users')
        if not no_email:
            self.stdout.write(f'  - Send {count} launch notification emails')

        confirm = input('\nAre you sure you want to proceed? [yes/N]: ')
        if confirm.lower() != 'yes':
            self.stdout.write(self.style.ERROR('Launch cancelled'))
            return

        # Launch platform
        self.stdout.write('\n' + '='*70)
        self.stdout.write('Launching platform...')
        launch_config.is_launched = True
        launch_config.save()
        self.stdout.write(self.style.SUCCESS('✓ Platform launched!'))

        # Remove waitlist status from all users
        self.stdout.write('Granting access to waitlisted users...')
        updated_count = waitlisted_users.update(is_waitlisted=False)
        self.stdout.write(self.style.SUCCESS(f'✓ Updated {updated_count} users'))

        # Send launch notification emails
        if not no_email:
            self.stdout.write('Sending notification emails...')
            self._send_launch_emails(waitlisted_users)
        else:
            self.stdout.write(self.style.WARNING('Skipping emails (--no-email flag)'))

        # Summary
        self.stdout.write('\n' + '='*70)
        self.stdout.write(self.style.SUCCESS('PLATFORM LAUNCH COMPLETE'))
        self.stdout.write('='*70)
        self.stdout.write(f'Launch time: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}')
        self.stdout.write(f'Users granted access: {updated_count}')
        if not no_email:
            self.stdout.write(f'Emails sent: {updated_count}')
        self.stdout.write('')

    def _send_launch_emails(self, users):
        """Send launch notification emails to all users with HTML and plain text."""
        email_count = 0
        failed_count = 0

        # Prepare email context
        site_url = getattr(settings, 'SITE_URL', 'https://app.zumodra.com')
        login_url = f'{site_url}/accounts/login/'
        dashboard_url = f'{site_url}/dashboard/'
        unsubscribe_url = f'{site_url}/accounts/email/preferences/'
        current_year = datetime.now().year
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@zumodra.com')

        for user in users:
            try:
                subject = 'Zumodra is Live! 🎉'

                # Context for email templates
                context = {
                    'user': user,
                    'login_url': login_url,
                    'dashboard_url': dashboard_url,
                    'unsubscribe_url': unsubscribe_url,
                    'current_year': current_year,
                }

                # Render plain text version
                try:
                    text_content = render_to_string('emails/platform_launched.txt', context)
                except Exception as e:
                    # Fallback plain text
                    text_content = f"""ZUMODRA IS LIVE!

Hi {user.first_name or user.email},

Great news! Zumodra has officially launched and your account is now fully active.

Access your dashboard: {login_url}

Thank you for being an early adopter!

Welcome to Zumodra!
The Team at Zumodra
"""
                    self.stdout.write(self.style.WARNING(f'Failed to render text template for {user.email}: {e}'))

                # Create email message
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body=text_content,
                    from_email=from_email,
                    to=[user.email]
                )

                # Render and attach HTML version
                try:
                    html_content = render_to_string('emails/platform_launched.html', context)
                    msg.attach_alternative(html_content, "text/html")
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Failed to render HTML template for {user.email}: {e}'))
                    # Continue with plain text only

                # Send email
                msg.send(fail_silently=False)
                email_count += 1

                # Progress indicator
                if email_count % 10 == 0:
                    self.stdout.write(f'  Sent {email_count} emails...')

            except Exception as e:
                failed_count += 1
                self.stdout.write(
                    self.style.ERROR(f'Failed to send email to {user.email}: {e}')
                )

        # Summary
        if email_count > 0:
            self.stdout.write(self.style.SUCCESS(f'✓ Sent {email_count} emails successfully'))
        if failed_count > 0:
            self.stdout.write(self.style.ERROR(f'✗ Failed to send {failed_count} emails'))
        if email_count == 0:
            self.stdout.write(self.style.WARNING('No emails sent'))
