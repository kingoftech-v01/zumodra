#!/usr/bin/env python
"""
Add pagination_class to all HR Core ViewSets that are missing it.
"""

import re

# Read the file
with open('hr_core/views.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all ViewSet classes that don't have pagination_class
viewset_pattern = r'(class \w+ViewSet\([^)]+\):.*?)(    queryset|    serializer_class|    permission_classes)'

def add_pagination(match):
    class_def = match.group(1)
    next_line = match.group(2)

    # Check if pagination_class already exists in this class
    if 'pagination_class' in class_def:
        return match.group(0)

    # Find the first attribute line after the class def and docstring
    # Insert pagination_class before the first queryset/serializer_class/permission_classes
    return class_def + '    pagination_class = StandardPagination\n' + next_line

# Apply the replacement
new_content = re.sub(viewset_pattern, add_pagination, content, flags=re.DOTALL)

# Write the modified content
with open('hr_core/views.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Pagination added to HR Core ViewSets")
