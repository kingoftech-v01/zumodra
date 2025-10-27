from django.db import models
from zumodra import settings
from django.utils import timezone
import uuid
from decimal import Decimal
from django.utils import timezone
from django.contrib.auth.models import Group, Permission
from configurations.models import *
# from django.contrib.gis.db import models as gis_models

User = settings.AUTH_USER_MODEL

# Create your models here.
#____________________PLATEFORME DE SERVICES & GESTION DES CONTRATS____________________#

class ServiceCategory(models.Model):
    """
    Catégorisation des services, permet l’imbrication de sous-catégories.
    """
    name = models.CharField(
        max_length=100, unique=True, help_text="Nom de la catégorie"
    )
    parent = models.ForeignKey(
        'self', on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='subcategories',
        help_text="Catégorie parent, pour structure arborescente"
    )
    description = models.TextField(blank=True, help_text="Description facultative")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")
    updated_at = models.DateTimeField(auto_now=True, help_text="Date de mise à jour")

    def __str__(self):
        return self.name if not self.parent else f"{self.parent} > {self.name}"


class ServicesTag(models.Model):
    tag = models.CharField(max_length=50, unique=True, help_text="Nom du tag (unique)")
    def __str__(self):
        return f"{self.tag}"

class ServicesPicture(models.Model):
    image = models.ImageField(upload_to='service_pictures/')
    description = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.service.name}"

class ProviderSkill(models.Model):
    provider = models.ForeignKey('ServiceProviderProfile', on_delete=models.CASCADE, related_name='provider_skills')
    skill = models.ForeignKey(Skill, on_delete=models.CASCADE, related_name='provider_skills')
    level = models.CharField(
        max_length=20,
        choices=[('beginner','Débutant'), ('intermediate','Intermédiaire'), ('expert','Expert')],
        default='beginner'
    )
    class Meta:
        unique_together = ('provider', 'skill')

# Prestataires de services (ServiceProviderProfile) avec compétences, catégories, localisation, tarifs, etc.
class ServiceProviderProfile(models.Model):
    """
    Extending existing profile with skills and service categories.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='service_provider_profile')
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, blank=True, related_name='providers')
    skills = models.ManyToManyField(ProviderSkill, blank=True)
    bio = models.TextField(blank=True)
    categories = models.ManyToManyField(ServiceCategory, blank=True)
    rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)  # aggregated rating 0-5
    completed_jobs = models.PositiveIntegerField(default=0)
    location_lat = models.FloatField(null=True, blank=True)
    location_lon = models.FloatField(null=True, blank=True)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2)
    rating_avg = models.DecimalField(max_digits=3, decimal_places=2, default=Decimal('0.00'))
    total_reviews = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)
    services = models.ManyToManyField('Service', blank=True, related_name='service_providers')
    availability_status = models.CharField(max_length=20, choices=[('available', 'Available'), ('unavailable', 'Unavailable')], default='available')
    is_verified = models.BooleanField(default=False)
    is_private = models.BooleanField(default=False)

    def __str__(self):
        return f"Provider: {self.user}"

# Services offerts par l’entreprise
class Service(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='services_offered_by_provider')
    serviceCategory = models.ForeignKey(ServiceCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='services')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    price = models.PositiveIntegerField(null=True, blank=True)  # prix indicatif
    duration_minutes = models.PositiveIntegerField(null=True, blank=True)  # durée estimée
    thumbnail = models.ImageField(upload_to='service_thumbnails/', blank=True, null=True)
    images = models.ManyToManyField(ServicesPicture, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.provider.user.first_name} {self.provider.user.last_name})"
    
class ServiceLike(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='liked_services')
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='likes')
    liked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'service')

    def __str__(self):
        return f"{self.user.email} likes {self.service.name}"

# Request clients (ClientRequest) avec critères de recherche, budget, localisation, etc.
class ClientRequest(models.Model):
    """
    Represents a client’s service request including skills required,
    location preferences, budget, and other parameters.
    """
    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name='requests')
    required_skills = models.ManyToManyField(Skill, blank=True)
    service_category = models.ForeignKey(ServiceCategory, on_delete=models.SET_NULL, null=True, blank=True)
    budget_min = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    budget_max = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    location_lat = models.FloatField(null=True, blank=True)
    location_lon = models.FloatField(null=True, blank=True)
    remote_allowed = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"Request by {self.client} for {self.service_category}"


class Match(models.Model):
    """
    Stores a match between a ClientRequest and a ServiceProviderProfile,
    along with a score computed by AI or heuristics.
    """
    client_request = models.ForeignKey(ClientRequest, on_delete=models.CASCADE, related_name='matches')
    provider_profile = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='matches')
    score = models.DecimalField(max_digits=5, decimal_places=4)  # value between 0 and 1 or 0 and 100
    matched_at = models.DateTimeField(auto_now_add=True)
    viewed_by_client = models.BooleanField(default=False)
    accepted_by_client = models.BooleanField(default=False)

    def __str__(self):
        return f"Match {self.client_request} - {self.provider_profile} : {self.score}"

class ServiceRequest(models.Model):
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='service_requests')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='service_requests')
    title = models.CharField(max_length=255)
    description = models.TextField()
    required_skills = models.ManyToManyField(Skill, related_name='service_requests', blank=True)
    budget_min = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    budget_max = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    deadline = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_open = models.BooleanField(default=True)

class ServiceProposal(models.Model):
    request = models.ForeignKey(ServiceRequest, on_delete=models.CASCADE, related_name='proposals')
    provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='proposals')
    proposed_rate = models.DecimalField(max_digits=10, decimal_places=2)
    message = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    is_accepted = models.BooleanField(default=False)
    class Meta:
        unique_together = ('request', 'provider')

class ServiceContract(models.Model):
    request = models.OneToOneField(ServiceRequest, on_delete=models.CASCADE, related_name='contract')
    provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='contracts')
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='contracts')
    agreed_rate = models.DecimalField(max_digits=10, decimal_places=2)
    agreed_deadline = models.DateField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[('pending','En attente'), ('active','Active'), ('completed','Terminée'), ('cancelled','Annulée')],
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

# class ProviderReport(models.Model):
#     provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='reports')
#     contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='reports')
#     report = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)

class ServiceComment(models.Model):
    """
    Review on a Service, avec possibilité de répondre à un autre commentaire.
    """
    provider = models.ForeignKey(
        ServiceProviderProfile, related_name='comments',
        on_delete=models.CASCADE,
        help_text="Professionnel associé au commentaire"
    )
    service = models.ForeignKey(
        Service, related_name='comments_service',
        on_delete=models.CASCADE,
        help_text="Service associé au commentaire"
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        help_text="Auteur du commentaire"
    )
    content = models.TextField(help_text="Contenu du commentaire", blank=True)
    rating = models.PositiveSmallIntegerField()
    created_at = models.DateTimeField(auto_now_add=True, help_text="Date de création")
    updated_at = models.DateTimeField(auto_now=True, help_text="Date de mise à jour")
    parent = models.ForeignKey(
        'self',
        null=True, blank=True,
        related_name='replies',
        on_delete=models.CASCADE,
        help_text="Commentaire parent si ce commentaire est une réponse"
    )

    def __str__(self):
        return f"Comment by {self.reviewer} on {self.service}"

    class Meta:
        ordering = ['-created_at']

class ServiceMessage(models.Model):
    contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    message = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)


# Audit logs
# Audit logs
from auditlog.registry import auditlog
from .models import (
    ServiceCategory, ServicesTag, ServicesPicture,
    ProviderSkill, ServiceProviderProfile, Service,
    ServiceLike, ClientRequest, Match,
    ServiceRequest, ServiceProposal, ServiceContract,
    ServiceComment, ServiceMessage
)

# Enregistrement de tous les modèles
auditlog.register(ServiceCategory)
auditlog.register(ServicesTag)
auditlog.register(ServicesPicture)
auditlog.register(ProviderSkill)
auditlog.register(ServiceProviderProfile)
auditlog.register(Service)
auditlog.register(ServiceLike)
auditlog.register(ClientRequest)
auditlog.register(Match)
auditlog.register(ServiceRequest)
auditlog.register(ServiceProposal)
auditlog.register(ServiceContract)
auditlog.register(ServiceComment)
auditlog.register(ServiceMessage)
