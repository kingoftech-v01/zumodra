#!/usr/bin/env python3
"""
Update URL namespace references from 'accounts:' to 'tenant_profiles:'
"""

import os
import re
from pathlib import Path

# Get project root
base_dir = Path(__file__).resolve().parent

# Patterns to replace
replacements = [
    # reverse() calls
    (r"reverse\('accounts:", "reverse('tenant_profiles:"),
    (r'reverse\("accounts:', 'reverse("tenant_profiles:'),

    # url template tag
    (r"{% url 'tenant_profiles:", "{% url 'tenant_profiles:"),
    (r'{% url "tenant_profiles:', '{% url "tenant_profiles:'),
]

# Exclude patterns
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
    '/migrations/',
    '.pyc',
    '.pyo',
]

# File extensions to process
extensions = {'.py', '.html', '.txt', '.md'}

print('\n' + '=' * 80)
print('URL NAMESPACE UPDATES: accounts: → tenant_profiles:')
print('=' * 80 + '\n')

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

            print(f'   ✅ {relative_path} ({file_replacements} replacements)')

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
    print('\n✅ URL NAMESPACE UPDATES COMPLETE!\n')
else:
    print('\n No files needed updating.')
