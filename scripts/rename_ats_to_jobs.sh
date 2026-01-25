#!/bin/bash
# Script to rename all 'ats' references to 'jobs' across the codebase
# Usage: bash scripts/rename_ats_to_jobs.sh

echo "=== Renaming 'ats' to 'jobs' across codebase ==="

# Exclude patterns
EXCLUDE_DIRS="--exclude-dir=venv --exclude-dir=.venv --exclude-dir=__pycache__ --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=staticfiles"
EXCLUDE_FILES="--exclude=*.pyc --exclude=*.pyo --exclude=*.log --exclude=*.sqlite3"

# 1. Replace 'ats.' references (model lazy references like 'ats.JobPosting')
echo "1. Replacing 'ats.' lazy references..."
find . -type f \( -name "*.py" -o -name "*.html" -o -name "*.js" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'ats\./'jobs\./g" {} +

# 2. Replace "ats." references
find . -type f \( -name "*.py" -o -name "*.html" -o -name "*.js" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/"ats\./"jobs\./g' {} +

# 3. Replace from ats. imports
echo "2. Replacing 'from ats.' imports..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/from ats\./from jobs\./g" {} +

# 4. Replace import ats references
echo "3. Replacing 'import ats' references..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/import ats\./import jobs\./g" {} +

# 5. Replace ('ats', in migrations and other tuples
echo "4. Replacing ('ats', references..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/('ats',/('jobs',/g" {} +

# 6. Replace URL namespaces: 'ats:' -> 'jobs:'
echo "5. Replacing URL namespace 'ats:' references..."
find . -type f \( -name "*.py" -o -name "*.html" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'ats:/'jobs:/g" {} +
find . -type f \( -name "*.py" -o -name "*.html" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/"ats:/"jobs:/g' {} +

# 7. Replace app_label = 'ats'
echo "6. Replacing app_label='ats' references..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/app_label = 'ats'/app_label = 'jobs'/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/app_label = "ats"/app_label = "jobs"/g' {} +

# 8. Replace 'ats' in INSTALLED_APPS lists
echo "7. Replacing 'ats' in INSTALLED_APPS..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'ats'/'jobs'/g" {} +

# 9. Replace template paths: ats/ -> jobs/
echo "8. Replacing template paths 'ats/' -> 'jobs/'..."
find . -type f \( -name "*.py" -o -name "*.html" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s#'ats/#'jobs/#g" {} +
find . -type f \( -name "*.py" -o -name "*.html" \) \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's#"ats/#"jobs/#g' {} +

# 10. Replace {% load ats_tags %} -> {% load jobs_tags %}
echo "9. Replacing template tags 'ats_tags' -> 'jobs_tags'..."
find . -type f -name "*.html" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/{% load ats_tags %}/{% load jobs_tags %}/g" {} +

# 11. Replace logger names
echo "10. Replacing logger names..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/logger = logging.getLogger('ats/logger = logging.getLogger('jobs/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/logger = logging.getLogger("ats/logger = logging.getLogger("jobs/g' {} +

echo "=== Renaming complete! ==="
echo "Files modified:"
grep -rl "jobs" . --include="*.py" --include="*.html" --exclude-dir=venv --exclude-dir=.venv --exclude-dir=__pycache__ | wc -l
