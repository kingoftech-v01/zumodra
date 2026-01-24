#!/bin/bash
# Script to fix remaining finance app references
# Note: Most finance models need to be changed on a case-by-case basis
# Usage: bash scripts/rename_finance_refs.sh

echo "=== Fixing finance references ==="

# 1. Replace finance.EscrowTransaction -> escrow.EscrowTransaction
echo "1. Replacing finance.EscrowTransaction references..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'finance\.EscrowTransaction'/'escrow.EscrowTransaction'/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/"finance\.EscrowTransaction"/"escrow.EscrowTransaction"/g' {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'finance\.escrowtransaction'/'escrow.escrowtransaction'/g" {} +

# 2. Replace finance.PaymentTransaction -> payments.PaymentTransaction
echo "2. Replacing finance.PaymentTransaction references..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i "s/'finance\.PaymentTransaction'/'payments.PaymentTransaction'/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" \
    -exec sed -i 's/"finance\.PaymentTransaction"/"payments.PaymentTransaction"/g' {} +

# 3. Replace from finance. imports that we know about
echo "3. Replacing known finance imports..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" -not -path "*/finance/*" \
    -exec sed -i "s/from finance\.models import EscrowTransaction/from escrow.models import EscrowTransaction/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" -not -path "*/finance/*" \
    -exec sed -i "s/from finance\.models import PaymentTransaction/from payments.models import PaymentTransaction/g" {} +
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" -not -path "*/finance/*" \
    -exec sed -i "s/from finance\.models import Dispute/from escrow.models import Dispute/g" {} +

# 4. Replace ('finance', in tuples
echo "4. Replacing ('finance', references in non-finance files..."
find . -type f -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" -not -path "*/.git/*" -not -path "*/finance/*" \
    -exec sed -i "s/('finance',/('payments',/g" {} +

echo "=== Finance reference fixes complete! ==="
