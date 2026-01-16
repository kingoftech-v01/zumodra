"""
Management command to seed the skill taxonomy database.

Seeds the SkillTaxonomy model with a comprehensive list of
technical and soft skills for AI-powered matching.
"""
import logging
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import transaction

from ai_matching.models import SkillTaxonomy

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Seed the skill taxonomy with predefined skills'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing skills before seeding',
        )
        parser.add_argument(
            '--fixture',
            type=str,
            default='skill_taxonomy.json',
            help='Fixture file to load (default: skill_taxonomy.json)',
        )

    def handle(self, *args, **options):
        """Seed skill taxonomy from fixtures."""
        clear_existing = options['clear']
        fixture_file = options['fixture']

        self.stdout.write(
            self.style.SUCCESS('Starting skill taxonomy seeding...')
        )

        try:
            # Clear existing data if requested
            if clear_existing:
                self.stdout.write('Clearing existing skills...')
                with transaction.atomic():
                    deleted_count, _ = SkillTaxonomy.objects.all().delete()
                    self.stdout.write(
                        self.style.WARNING(
                            f'Deleted {deleted_count} existing skills'
                        )
                    )

            # Load fixtures
            self.stdout.write(f'Loading skills from {fixture_file}...')
            try:
                call_command(
                    'loaddata',
                    fixture_file,
                    app_label='ai_matching',
                    verbosity=2,
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'Failed to load fixture: {e}\n'
                        f'Trying with absolute path...'
                    )
                )
                # Try with full path
                import os
                from django.conf import settings

                # Get ai_matching app directory
                from ai_matching import __file__ as app_init
                app_dir = os.path.dirname(app_init)
                fixture_path = os.path.join(app_dir, 'fixtures', fixture_file)

                if os.path.exists(fixture_path):
                    call_command('loaddata', fixture_path, verbosity=2)
                else:
                    raise FileNotFoundError(
                        f'Fixture file not found: {fixture_path}'
                    )

            # Display summary
            total_skills = SkillTaxonomy.objects.count()
            skills_by_category = {}

            for skill in SkillTaxonomy.objects.all():
                category = skill.category or 'uncategorized'
                skills_by_category[category] = skills_by_category.get(category, 0) + 1

            self.stdout.write(
                self.style.SUCCESS(
                    f'\n✓ Successfully seeded {total_skills} skills!'
                )
            )

            self.stdout.write('\nSkills by category:')
            for category, count in sorted(skills_by_category.items()):
                self.stdout.write(f'  - {category}: {count}')

            # Display sample skills
            self.stdout.write('\nSample skills:')
            for skill in SkillTaxonomy.objects.all()[:10]:
                synonyms = ', '.join(skill.synonyms[:3]) if skill.synonyms else 'none'
                self.stdout.write(
                    f'  - {skill.name} ({skill.category}) '
                    f'[synonyms: {synonyms}]'
                )

            self.stdout.write(
                self.style.SUCCESS(
                    '\n✓ Skill taxonomy seeding completed successfully!'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'\n✗ Seeding failed: {str(e)}')
            )
            logger.exception('Skill taxonomy seeding failed')
            raise
