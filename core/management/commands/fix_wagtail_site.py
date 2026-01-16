"""
Management command to fix Wagtail Site configuration.

This command resolves the issue where Wagtail's root_page is pointing to a ContentType
object instead of a proper Page object, which causes 'ContentType' object has no attribute 'route' errors.

The root cause is that Wagtail's Site.root_page is a ForeignKey to Page, but sometimes
gets corrupted and points to the wrong object type.

Usage:
    python manage.py fix_wagtail_site
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from wagtail.models import Site, Page
from django.contrib.contenttypes.models import ContentType


class Command(BaseCommand):
    help = 'Fix Wagtail Site configuration - ensures root_page is a valid Page object'

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('=== Wagtail Site Configuration Fix ==='))
        self.stdout.write('')

        # Check current state
        sites = Site.objects.all()
        self.stdout.write(f'Found {sites.count()} Wagtail Site(s)')
        self.stdout.write('')

        issues_found = False

        for site in sites:
            self.stdout.write(f'Checking Site {site.id}:')
            self.stdout.write(f'  - Hostname: {site.hostname}')
            self.stdout.write(f'  - Port: {site.port}')
            self.stdout.write(f'  - Is default: {site.is_default_site}')
            self.stdout.write(f'  - Root page ID: {site.root_page_id}')

            try:
                root = site.root_page

                # Check if root_page is actually a Page instance
                if not isinstance(root, Page):
                    self.stdout.write(
                        self.style.ERROR(
                            f'  - ERROR: Root page is {type(root).__name__}, not Page!'
                        )
                    )
                    issues_found = True

                    # Try to fix by finding or creating a proper root page
                    self._fix_root_page(site)
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  - OK: Root page is valid Page: "{root.title}"'
                        )
                    )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  - ERROR: Failed to access root page: {e}')
                )
                issues_found = True
                self._fix_root_page(site)

            self.stdout.write('')

        if not issues_found:
            self.stdout.write(self.style.SUCCESS('All Wagtail Sites are configured correctly!'))
        else:
            self.stdout.write(
                self.style.SUCCESS('Site configuration has been fixed. Please test your URLs.')
            )

    @transaction.atomic
    def _fix_root_page(self, site):
        """
        Fix a corrupted root_page by finding or creating a proper Page object.

        This handles the case where Site.root_page points to a ContentType instead
        of a Page, which happens when the Wagtail database is not properly initialized.
        """
        self.stdout.write('  - Attempting to fix root page...')

        # Try to find an existing root page (depth=1 means root level in Wagtail's tree)
        try:
            root_pages = Page.objects.filter(depth=1)

            if root_pages.exists():
                # Use the first root page found
                new_root = root_pages.first()
                self.stdout.write(f'  - Found existing root page: "{new_root.title}" (ID: {new_root.id})')

                site.root_page = new_root
                site.save()

                self.stdout.write(
                    self.style.SUCCESS(
                        f'  - Fixed: Site now points to page "{new_root.title}"'
                    )
                )
            else:
                # No root pages exist - create one
                self.stdout.write('  - No root pages found. Creating a new root page...')

                # Create a root page
                root_page = Page(
                    title='Root',
                    slug='root',
                    depth=1,
                    path='0001',
                    numchild=0,
                )
                root_page.save()

                site.root_page = root_page
                site.save()

                self.stdout.write(
                    self.style.SUCCESS(
                        f'  - Created new root page "{root_page.title}" (ID: {root_page.id})'
                    )
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  - Failed to fix root page: {e}')
            )
            raise
