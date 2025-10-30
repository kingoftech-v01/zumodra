from django.db import models
from zumodra import settings
from django.utils import timezone
import uuid
from decimal import Decimal
from django.utils import timezone
from django.contrib.auth.models import Group, Permission
from configurations.models import *

User = settings.AUTH_USER_MODEL

# Create your models here.
#_______________Gestion des Projets et Contrats________________#

class ProjectCategory(models.Model):
    """
    Represents the category or sector of a project.
    """
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name

class ProjectsTag(models.Model):
    tag = models.CharField(max_length=50)
    def __str__(self):
        return f"{self.tag}"

class ProjectType(models.Model):
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name

class ProjectClientProfile(models.Model):
    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name='client_profile')
    company = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ProjectProviderProfile(models.Model):
    provider = models.ForeignKey(User, on_delete=models.CASCADE, related_name='project_provider_profile')
    company = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ProjectRequest(models.Model):
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='project_requests')
    title = models.CharField(max_length=255)
    description = models.TextField()
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    deadline = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_open = models.BooleanField(default=True)

class Project(models.Model):
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='projects')
    title = models.CharField(max_length=255)
    description = models.TextField()
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    deadline = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=[('pending','En attente'), ('active','Active'), ('completed','Terminée'), ('cancelled','Annulée')],
        default='pending'
    )
    class Meta:
        unique_together = ('client', 'title')

class ContractProject(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='contracts')
    provider = models.ForeignKey(ProjectProviderProfile, on_delete=models.CASCADE, related_name='contracts')
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

class ProviderReviewProject(models.Model):
    contract = models.ForeignKey(ContractProject, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='project_reviews')
    rating = models.IntegerField()
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)