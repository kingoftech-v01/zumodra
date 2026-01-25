#!/usr/bin/env python3
"""
Direct import update script - doesn't require Django
Updates all imports from accounts → tenant_profiles
"""

import os
import re
from pathlib import Path

# Get project root
base_dir = Path(__file__).resolve().parent

# Patterns to replace
replacements = [
    # accounts → tenant_profiles (excluding 'accounts.google.com' etc.)
    (r'from accounts\.', 'from tenant_profiles.'),
    (r'import accounts\.', 'import tenant_profiles.'),
    (r'\baccounts\.models\b', 'tenant_profiles.models'),
    (r'\baccounts\.serializers\b', 'tenant_profiles.serializers'),
    (r'\baccounts\.views\b', 'tenant_profiles.views'),
    (r'\baccounts\.template_views\b', 'tenant_profiles.template_views'),
    (r'\baccounts\.services\b', 'tenant_profiles.services'),
    (r'\baccounts\.signals\b', 'tenant_profiles.signals'),
    (r'\baccounts\.permissions\b', 'tenant_profiles.permissions'),
    (r'\baccounts\.forms\b', 'tenant_profiles.forms'),
    (r"'accounts\.", "'tenant_profiles."),
    (r'"accounts\.', '"tenant_profiles.'),
    (r'\(accounts\.', '(tenant_profiles.'),
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
    'update_imports',  # Don't modify this file
    'migrate_to_tenant_profiles.py',
]

# File extensions to process
extensions = {'.py', '.md', '.txt', '.rst'}

print('\n' + '=' * 80)
print('IMPORT UPDATES: accounts → tenant_profiles')
print('=' * 80 + '\n')

print('🔍 Scanning for files...\n')

total_files_scanned = 0
total_files_modified = 0
total_replacements = 0
modified_files = []

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

            print(f'   ✅ {relative_path} ({file_replacements} replacements)')

            modified_files.append(relative_path)
            total_files_modified += 1
            total_replacements += file_replacements

            # Write file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)

# Summary
print('\n' + '=' * 80)
print('📊 SUMMARY')
print('=' * 80 + '\n')

print(f'Files scanned: {total_files_scanned}')
print(f'✅ Files modified: {total_files_modified}')
print(f'✅ Total replacements: {total_replacements}')

if total_files_modified > 0:
    print('\n✅ IMPORT UPDATES COMPLETE!\n')
    print('Next steps:')
    print('1. Review changes with: git diff')
    print('2. Run Django system check: python manage.py check')
    print('3. Run tests to verify no broken imports')
    print('4. Commit changes to version control\n')
else:
    print('\n No files needed updating.')
