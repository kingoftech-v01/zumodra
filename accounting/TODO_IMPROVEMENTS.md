# TODO & IMPROVEMENTS - accounting
## Date: 2026-01-25
## Statut: ✅ FONCTIONNEL

---

## ✅ CORRECTIONS APPLIQUÉES (CYCLE 1)

### Serializers Corrigés
- ✅ `AccountingProviderListSerializer` - Remplacé `is_active` par `status`
- ✅ `AccountingProviderDetailSerializer` - Ajouté champs manquants
- ✅ `ChartOfAccountsDetailSerializer` - Retiré `metadata`, ajouté `current_balance`
- ✅ `JournalEntryListSerializer` - Corrigé `date` → `entry_date`
- ✅ `JournalEntryDetailSerializer` - Corrigé `date` → `entry_date`
- ✅ `JournalEntryLineSerializer` - Corrigé `account_code` → `account.account_number`

### Models Améliorés
- ✅ `JournalEntry` - Ajouté properties `total_debits` et `total_credits`

---

## 🎯 AMÉLIORATIONS SUGGÉRÉES

### Priorité CRITIQUE

#### 1. Encryption des Tokens OAuth
- **Description**: access_token et refresh_token stockés en clair
- **Suggestion**: Utiliser django-cryptography pour encryption
```python
from encrypted_model_fields.fields import EncryptedCharField

class AccountingProvider:
    access_token = EncryptedCharField(max_length=500)
    refresh_token = EncryptedCharField(max_length=500)
```
- **Impact**: SÉCURITÉ - Conformité GDPR/SOC2
- **Fichiers**: `models.py` ligne 47-57

#### 2. Validation Double-Entry Bookkeeping
- **Description**: is_balanced vérifie égalité mais pas de validation dans save()
- **Suggestion**: Forcer validation avant posting
```python
def save(self, *args, **kwargs):
    if self.status == 'posted' and not self.is_balanced:
        raise ValidationError("Cannot post unbalanced journal entry")
    super().save(*args, **kwargs)
```
- **Impact**: Intégrité comptable
- **Fichiers**: `models.py` JournalEntry.save()

#### 3. Token Refresh Automatique
- **Description**: is_token_expired détecte mais ne refresh pas
- **Suggestion**: Implémenter auto-refresh dans manager/service
```python
class AccountingProviderManager:
    def get_or_refresh_token(self, provider_id):
        provider = self.get(id=provider_id)
        if provider.is_token_expired:
            provider.refresh_oauth_token()  # À implémenter
        return provider
```
- **Impact**: Robustesse des intégrations

### Priorité HAUTE

#### 4. Audit Trail Complet
- **Description**: Journal entries modifiables sans trace
- **Suggestion**: Interdire modification après posting + audit log
```python
from auditlog.registry import auditlog

auditlog.register(JournalEntry)
auditlog.register(JournalEntryLine)

def save(self, *args, **kwargs):
    if self.pk and self.status == 'posted':
        raise ValidationError("Cannot modify posted entries")
```
- **Impact**: Conformité comptable
- **Fichiers**: `models.py`

#### 5. Reconciliation Automatique
- **Description**: ReconciliationRecord est manuel
- **Suggestion**: Ajouter algorithme de matching automatique
- **Impact**: Gain de temps, réduction d'erreurs
```python
class ReconciliationService:
    def auto_match_transactions(self, account, date_range):
        # Matching algorithm
        # - Exact amount match
        # - Date proximity (±3 days)
        # - Reference number match
        pass
```

#### 6. Rate Limiting sur Sync
- **Description**: Pas de protection contre trop de syncs
- **Suggestion**: Limiter selon sync_frequency
```python
def can_sync(self):
    if not self.last_sync:
        return True
    if self.sync_frequency == 'hourly':
        return (timezone.now() - self.last_sync).hours >= 1
    # ... autres fréquences
```
- **Impact**: Prévention abus API QuickBooks/Xero

### Priorité MOYENNE

#### 7. Webhooks pour Sync
- **Description**: Sync est polling-based
- **Suggestion**: Implémenter webhooks QuickBooks/Xero pour real-time
- **Impact**: Réduction latence, économie API calls

#### 8. Reporting Avancé
- **Description**: FinancialReport génère rapport mais pas de format
- **Suggestion**: Ajouter export PDF/Excel avec graphiques
```python
def generate_profit_loss(self, period_start, period_end):
    # Générer P&L avec:
    # - Revenue breakdown by account
    # - Expense categorization
    # - Net profit calculation
    # - Comparison vs previous period
    # - Export to PDF/Excel
```

#### 9. Multi-Currency Support
- **Description**: base_currency existe mais pas de conversion
- **Suggestion**: Intégrer API de taux de change (ex: exchangerate-api.com)
- **Impact**: Support entreprises internationales

#### 10. Bank Feed Integration
- **Description**: bank_balance manuel dans ReconciliationRecord
- **Suggestion**: Intégrer Plaid/Yodlee pour import automatique
- **Impact**: Automatisation complète

### Priorité BASSE

#### 11. Chart of Accounts Templates
- **Description**: Chaque tenant crée COA from scratch
- **Suggestion**: Fournir templates par industrie
```python
# templates/coa/retail.json
{
  "accounts": [
    {"number": "1000", "name": "Cash", "type": "asset"},
    {"number": "1100", "name": "Accounts Receivable", "type": "asset"},
    ...
  ]
}
```

#### 12. Batch Import
- **Description**: Journal entries un par un
- **Suggestion**: Endpoint pour CSV/Excel import
- **Impact**: Facilité migration/bulk operations

#### 13. Approval Workflow
- **Description**: Pas de processus d'approbation
- **Suggestion**: Ajouter workflow pour journal entries > $X
```python
class JournalEntry:
    requires_approval = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, ...)
    approved_at = models.DateTimeField(...)
```

---

## 🔒 SÉCURITÉ

### CRITIQUES
1. ❌ **Tokens OAuth non chiffrés** - RISQUE ÉLEVÉ
2. ⚠️ **Pas de validation permissions** - Qui peut créer journal entries?
3. ⚠️ **Soft delete manquant** - Entries supprimées perdues
4. ⚠️ **API keys QuickBooks/Xero exposées** - Utiliser secrets manager

### Recommandations
```python
# Permissions
from rest_framework.permissions import BasePermission

class IsAccountant(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='Accountants').exists()

class JournalEntryViewSet:
    permission_classes = [IsAccountant]
```

---

## 📊 COMPLIANCE & STANDARDS

### Standards Comptables
- [ ] Implement GAAP compliance checks
- [ ] Implement IFRS compliance checks
- [ ] Add period closing mechanism (prevent edits in closed periods)
- [ ] Implement retained earnings calculation

### Audit Requirements
- [ ] Complete audit trail for all transactions
- [ ] User attribution for all entries
- [ ] Timestamp accuracy (UTC only)
- [ ] Immutability after posting

---

## 🐛 BUGS POTENTIELS

1. **Race condition**: total_debits/credits calcul avec sum() peut être incorrect pendant writes
2. **Orphan lines**: JournalEntryLine sans entry si exception pendant create
3. **Timezone mismatch**: entry_date est Date mais synced_at est DateTime
4. **Cascade deletes**: Deleting AccountingProvider deletes all COA → cascade to all JournalEntryLines

---

## 📈 PERFORMANCE

### Optimisations Suggérées
1. **Index composites**:
```python
class Meta:
    indexes = [
        models.Index(fields=['provider', 'status', '-entry_date']),
        models.Index(fields=['account', 'entry__entry_date']),
    ]
```

2. **Denormalization**:
```python
class JournalEntry:
    total_debit_amount = models.DecimalField(...)  # Cached
    total_credit_amount = models.DecimalField(...)  # Cached
    # Update via signal on line save
```

3. **Prefetch related**:
```python
JournalEntry.objects.prefetch_related('lines__account').select_related('provider')
```

---

*Généré automatiquement par Claude Agent Testing System - Cycle 1*
