"""
Update Imports: custom_account_u → core_identity, accounts → tenant_profiles

This command automates the tedious task of updating all imports across the codebase.

Author: Zumodra Team
Date: 2026-01-17
"""

from django.core.management.base import BaseCommand
import os
import re
from pathlib import Path


class Command(BaseCommand):
    help = 'Update all imports from old app names to new app names'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without making changes',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']

        self.stdout.write(self.style.WARNING(
            '=' * 80
        ))
        self.stdout.write(self.style.WARNING(
            'IMPORT UPDATES: custom_account_u → core_identity, accounts → tenant_profiles'
        ))
        self.stdout.write(self.style.WARNING(
            '=' * 80
        ))

        if dry_run:
            self.stdout.write(self.style.NOTICE(
                '\n⚠️  DRY RUN MODE - No files will be modified\n'
            ))

        # Get project root
        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent

        # Patterns to replace
        replacements = [
            # custom_account_u → core_identity
            (r'from custom_account_u\.', 'from core_identity.'),
            (r'import custom_account_u\.', 'import core_identity.'),
            (r'import custom_account_u\b', 'import core_identity'),
            (r"'custom_account_u\.", "'core_identity."),
            (r'"custom_account_u\.', '"core_identity.'),

            # accounts → tenant_profiles (excluding 'accounts.google.com' etc.)
            (r'from accounts\.', 'from tenant_profiles.'),
            (r'import accounts\.', 'import tenant_profiles.'),
            (r'\baccounts\.models\b', 'tenant_profiles.models'),
            (r'\baccounts\.serializers\b', 'tenant_profiles.serializers'),
            (r'\baccounts\.views\b', 'tenant_profiles.views'),
            (r'\baccounts\.services\b', 'tenant_profiles.services'),
            (r'\baccounts\.signals\b', 'tenant_profiles.signals'),
            (r"'accounts\.", "'tenant_profiles."),
            (r'"accounts\.', '"tenant_profiles.'),
        ]

        # Exclude patterns (files/directories to skip)
        exclude_patterns = [
            '/venv/',
            '/env/',
            '/.venv/',
            '/node_modules/',
            '/staticfiles/',
            '/media/',
            '/__pycache__/',
            '/.git/',
            '/.pytest_cache/',
            '/migrations/',  # Don't modify migrations
            '.pyc',
            '.pyo',
            'update_imports.py',  # Don't modify this file
            'migrate_to_core_identity.py',  # Migration scripts are intentional
            'migrate_to_tenant_profiles.py',
        ]

        # File extensions to process
        extensions = {'.py', '.md', '.txt', '.rst'}

        self.stdout.write('\n🔍 Scanning for files...\n')

        total_files_scanned = 0
        total_files_modified = 0
        total_replacements = 0

        for root, dirs, files in os.walk(base_dir):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(
                excl in os.path.join(root, d) for excl in exclude_patterns
            )]

            for file in files:
                file_path = os.path.join(root, file)

                # Check if file should be excluded
                if any(excl in file_path for excl in exclude_patterns):
                    continue

                # Check file extension
                if not any(file.endswith(ext) for ext in extensions):
                    continue

                total_files_scanned += 1

                # Read file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except (UnicodeDecodeError, PermissionError):
                    continue

                # Apply replacements
                modified_content = content
                file_replacements = 0

                for pattern, replacement in replacements:
                    new_content = re.sub(pattern, replacement, modified_content)
                    if new_content != modified_content:
                        file_replacements += re.subn(pattern, replacement, modified_content)[1]
                        modified_content = new_content

                # If file was modified
                if modified_content != content:
                    relative_path = os.path.relpath(file_path, base_dir)

                    self.stdout.write(self.style.SUCCESS(
                        f'   ✅ {relative_path} ({file_replacements} replacements)'
                    ))

                    total_files_modified += 1
                    total_replacements += file_replacements

                    # Write file (if not dry run)
                    if not dry_run:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(modified_content)

        # Summary
        self.stdout.write('\n' + '=' * 80)
        self.stdout.write(self.style.SUCCESS('📊 SUMMARY'))
        self.stdout.write('=' * 80 + '\n')

        self.stdout.write(f'Files scanned: {total_files_scanned}')
        self.stdout.write(self.style.SUCCESS(
            f'✅ Files modified: {total_files_modified}'
        ))
        self.stdout.write(self.style.SUCCESS(
            f'✅ Total replacements: {total_replacements}'
        ))

        if dry_run:
            self.stdout.write(self.style.NOTICE(
                '\n⚠️  DRY RUN COMPLETE - No files were modified\n'
            ))
            self.stdout.write(self.style.NOTICE(
                'Run without --dry-run to apply changes.\n'
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                '\n✅ IMPORT UPDATES COMPLETE!\n'
            ))
            self.stdout.write(self.style.NOTICE(
                'Next steps:\n'
                '1. Run tests to verify no broken imports\n'
                '2. Check for any remaining manual updates needed\n'
                '3. Commit changes to version control\n'
            ))
