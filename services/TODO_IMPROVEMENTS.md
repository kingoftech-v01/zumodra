# TODO & IMPROVEMENTS - services
## Date: 2026-01-25
## Statut: ✅ FONCTIONNEL

---

## ✅ CORRECTIONS APPLIQUÉES (CYCLE 1)

### Fichiers Créés
- ✅ `urls_frontend.py` - Routes frontend séparées pour intégration avec core.urls_frontend

---

## 🎯 AMÉLIORATIONS SUGGÉRÉES

### Priorité HAUTE

#### 1. Validation des Prix
- **Description**: Les ServicePricingTier peuvent avoir des prix négatifs
- **Suggestion**: Ajouter MinValueValidator(0) sur tous les champs de prix
- **Impact**: Intégrité des données financières
- **Fichiers**: `models.py`

#### 2. Gestion des Images
- **Description**: ServiceImage n'a pas de limite de taille ou format
- **Suggestion**: Ajouter validation pour:
  - Formats acceptés (JPEG, PNG, WebP)
  - Taille max (5MB)
  - Dimensions min/max
  - Compression automatique
- **Impact**: Performance et sécurité

#### 3. Statut des Contrats
- **Description**: ServiceContract workflow peut être amélioré
- **Suggestion**: Ajouter machine à états avec transitions validées
```python
from django_fsm import FSMField, transition

class ServiceContract:
    status = FSMField(default='draft')

    @transition(field=status, source='draft', target='active')
    def activate(self):
        # Validation logic
        pass
```
- **Impact**: Prévention d'états invalides

### Priorité MOYENNE

#### 4. Cache des Reviews
- **Description**: get_average_rating recalcule à chaque appel
- **Suggestion**: Stocker dans un champ dénormalisé avec signal update
- **Impact**: Performance sur listes de services

#### 5. Recherche Full-Text
- **Description**: Recherche basique sur nom/description
- **Suggestion**: Intégrer PostgreSQL Full-Text Search ou Elasticsearch
- **Impact**: Qualité des résultats de recherche

#### 6. Versioning des Services
- **Description**: Modifications de service écrasent les données
- **Suggestion**: Ajouter historique avec django-simple-history
- **Impact**: Audit trail et possibilité de rollback

#### 7. Notifications
- **Description**: Pas de notifications sur événements contrat
- **Suggestion**: Intégrer avec app notifications pour:
  - Nouvelle demande de service
  - Proposition acceptée/refusée
  - Changement de statut contrat
  - Message contrat
- **Impact**: Engagement utilisateur

### Priorité BASSE

#### 8. Analytics
- **Description**: view_count et order_count sont simples
- **Suggestion**: Tracker métriques détaillées:
  - Taux de conversion (vues → demandes)
  - Temps moyen de réponse
  - Satisfaction client
- **Impact**: Business intelligence

#### 9. Export de Données
- **Description**: Pas de fonctionnalité d'export
- **Suggestion**: Ajouter endpoints pour export CSV/PDF:
  - Liste des services
  - Historique des contrats
  - Rapports financiers
- **Impact**: Facilité de gestion

#### 10. API Documentation
- **Description**: API endpoints manquent d'exemples
- **Suggestion**: Enrichir docstrings avec drf-spectacular decorators
```python
from drf_spectacular.utils import extend_schema, OpenApiParameter

@extend_schema(
    summary="List all services",
    parameters=[
        OpenApiParameter('category', str, description='Filter by category slug'),
    ],
    responses={200: ServiceListSerializer(many=True)}
)
def list(self, request):
    ...
```

---

## 🔒 SÉCURITÉ

### Recommandations CRITIQUES
1. ⚠️ **Validation des uploads**: Ajouter scan antivirus pour images/docs
2. ⚠️ **Rate limiting**: Protéger create_service_request contre spam
3. ⚠️ **Permissions**: Vérifier que seul le provider peut modifier son service
4. ✅ Cross-tenant requests bien isolés
5. ⚠️ Sanitize les descriptions HTML pour prévenir XSS

### Audit de Permissions
```python
# À vérifier dans views_api.py
class ServiceViewSet:
    def get_permissions(self):
        if self.action in ['create', 'update', 'destroy']:
            return [IsProvider()]  # ⚠️ À implémenter
        return [AllowAny()]  # ⚠️ Trop permissif?
```

---

## 📊 MÉTRIQUES ACTUELLES

- **Endpoints**: 15+ (services, providers, contracts, reviews)
- **Modèles**: 12 (Service, Provider, Contract, Review, etc.)
- **Serializers**: 10+
- **Tests**: À vérifier
- **URLs**: 2 fichiers (urls.py + urls_frontend.py)

---

## 🎯 MIGRATION SUGGÉRÉE

### De Monolithe vers Microservices (Long terme)
1. **Services Catalog** → Service séparé
2. **Contracts** → Service séparé avec event sourcing
3. **Reviews** → Service séparé
4. **Messaging** → Déjà séparé (messages_sys)

Avantages:
- Scalabilité indépendante
- Déploiements isolés
- Langages différents si besoin

---

## 🐛 BUGS POTENTIELS À INVESTIGUER

1. **Race condition**: increment view_count sans F() expression
2. **N+1 queries**: Dans browse_services avec reviews
3. **Memory leak**: Si ServiceImage.image pas nettoyé après delete
4. **Timezone**: created_at utilise auto_now mais timezone peut être inconsistent

---

*Généré automatiquement par Claude Agent Testing System - Cycle 1*
