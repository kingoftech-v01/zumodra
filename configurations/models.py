from django.db import models
from zumodra import settings
from django.utils import timezone
import uuid
from decimal import Decimal
from django.utils import timezone
from django.contrib.auth.models import Group, Permission

User = settings.AUTH_USER_MODEL


# Create your models here.

class ServiceCategory(models.Model):
    """
    Represents the category or sector of service.
    """
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Skill(models.Model):
    """
    Represents a skill or competency.
    Used to tag service providers and filter clients' needs.
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

#____________________COMPANY & HR MODELS____________________#

# Entreprise (Company)
class Company(models.Model): # Alias Organization
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    domain = models.CharField(max_length=255, blank=True, null=True)
    industry = models.CharField(max_length=120, blank=True)
    logo = models.ImageField(upload_to='company_logos/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.name

# Nouvelle entité : Site ou Filiale (Branch)
class Site(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='sites')
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=512, blank=True)
    city = models.CharField(max_length=128, blank=True)
    country = models.CharField(max_length=64, blank=True)
    phone = models.CharField(max_length=30, blank=True)
    email = models.EmailField(blank=True)
    established_date = models.DateField(null=True, blank=True)
    number_of_employees = models.PositiveIntegerField(default=1)
    is_main_office = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('company', 'name')

    def __str__(self):
        return f"{self.name} ({self.company.name})"
    
class CompanyProfile(models.Model):
    company = models.OneToOneField(Company, on_delete=models.CASCADE, related_name='profile')
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name='profiles')
    description = models.TextField(blank=True)
    website = models.URLField(blank=True, null=True)
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)
    facebook_url = models.URLField(blank=True)
    instagram_url = models.URLField(blank=True)

    def __str__(self):
        return f"Profil {self.company.name}"

# Départements rattachés à un ou plusieurs sites (optionnel selon besoin)
# On considère le lien many to one classique ici (un département dans un seul site)
class Department(models.Model):
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='departments')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    class Meta:
        unique_together = ('company', 'name')

    def __str__(self):
        return f"{self.name} - {self.company.name}"
    
# Poste/Rôle métier (Role) lié à une entreprise, optionnellement à un site
class Role(models.Model):
    """
    Modélise un rôle métier (ex: "Manager", "Comptable", "RH", "Employé simple") spécifique à l'application/entreprise
    Possibilité de lier aux Groupes Django natifs pour héritage de permissions
    """
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='roles')
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)
    group = models.OneToOneField(Group, on_delete=models.CASCADE, null=True, blank=True)
    permissions = models.ManyToManyField(
        Permission, blank=True, related_name='org_role_permissions'
    )

    class Meta:
        unique_together = ('company', 'name')

    def __str__(self):
        return f"{self.name} - {self.company.name}"

# Employés (Membership) rattachés à un Profil d’entreprise, avec option de département et rôle   
class Membership(models.Model):
    """
    'Profil' contextuel : relie un user générique à une entreprise, avec option de département, et gère les rôles/permissions locaux.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='memberships')
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='memberships')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='memberships')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True, related_name='memberships')
    job_title = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user_permissions = models.ManyToManyField(
        Permission, blank=True, related_name='org_membership_permissions'
    )

    def __str__(self):
        return f"{self.user.email} ({self.company.company.name}) -- {self.role.name if self.role else 'No Role'}"

    class Meta:
        unique_together = ('user', 'company')

    def get_all_permissions(self):
        # Permissions inherit from Role (Group) + direct ManyToMany
        perms = set()
        if self.role and self.role.group:
            perms |= set(self.role.group.permissions.values_list('codename', flat=True))
        perms |= set(self.user_permissions.values_list('codename', flat=True))
        return perms

    def has_perm(self, codename):
        return codename in self.get_all_permissions()

#____________________RECRUITMENT & HR MODELS____________________#

# Profil candidat indépendant (CandidateProfile)
#  Profil principal du candidat associé à un utilisateur
class CandidateProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='candidate_profile')
    resume = models.FileField(upload_to='resumes/', blank=True, null=True)
    bio = models.TextField(blank=True)  # présentation, résumé personnel
    phone = models.CharField(max_length=30, blank=True)
    linkedin_url = models.URLField(blank=True)
    github_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)
    skills = models.ManyToManyField(Skill, blank=True)  # competences professionnelles
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Candidat: {self.user.email}"

# Poste au sein d’une entreprise/dept (JobPosition)
# Emplois et postes également liés à un site pour localisation précise
class JobPosition(models.Model):
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='positions')
    site = models.ForeignKey(Site, on_delete=models.SET_NULL, null=True, blank=True, related_name='positions')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='positions')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_open = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('company', 'site', 'department', 'title')

    def __str__(self):
        site_name = self.site.name if self.site else "Sans site"
        dept_name = self.department.name if self.department else "Sans département"
        return f"{self.title} ({site_name} | {dept_name}) - {self.company.name}"



# Emploi/Annonce d’offre (Job)
class Job(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='jobs')
    position = models.ForeignKey(JobPosition, on_delete=models.CASCADE, related_name='jobs')
    title = models.CharField(max_length=255)
    description = models.TextField()
    requirements = models.TextField(blank=True)
    salary_from = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    salary_to = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    posted_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    # service = models.ForeignKey(Service, null=True, blank=True, on_delete=models.SET_NULL, related_name='jobs')
    def __str__(self):
        return f"{self.title} ({self.company.name})"

# Candidature à un emploi (JobApplication)
class JobApplication(models.Model):
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='applications')
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications') # Job venant des modèles entreprise/recrutement
    cover_letter = models.TextField(blank=True)
    status = models.CharField(
        choices=[
            ('pending', 'En attente'),
            ('reviewed', 'En cours de traitement'),
            ('interview', 'Entretien'),
            ('offered', 'Offre envoyée'),
            ('accepted', 'Acceptée'),
            ('rejected', 'Refusée')
        ],
        max_length=20,
        default='pending'
    )
    applied_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return f"Candidature de {self.candidate.user.email} pour {self.job.title} ({self.status})"

# Dossier employé lié à une adhésion (Membership)
class EmployeeRecord(models.Model):
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE, related_name='employee_records')
    hire_date = models.DateField()
    contract_type = models.CharField(
        choices=[
            ('cdi','CDI'),
            ('cdd','CDD'),
            ('contract','Contrat'),
            ('intern','Stagiaire')
            ],
        max_length=15, default='cdi'
    )
    salary = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        choices=[('active','Actif'),
                 ('terminated','Terminé'),
                 ('on_leave','En congé')
                ],
        max_length=12, default='active'
    )
    resignation_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)

class ContractDocument(models.Model):
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='contracts')
    upload = models.FileField(upload_to='contracts/')
    description = models.TextField(blank=True)
    signed_at = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

class Interview(models.Model):
    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='interviews')
    interviewer = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True)
    interviewee = models.ForeignKey(CandidateProfile, on_delete=models.SET_NULL, null=True)
    scheduled_at = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    location = models.CharField(max_length=255, blank=True)
    mode = models.CharField(
        choices=[('in_person','Présentiel'),('remote','Remote'),('phone','Téléphone')], max_length=12, default='remote'
    )
    status = models.CharField(
        choices=[('scheduled','Planifiée'),('completed','Terminée'),('absent','Non venu')], max_length=12, default='scheduled'
    )
    summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class InterviewNote(models.Model):
    interview = models.ForeignKey(Interview, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True)
    note = models.TextField()
    rating = models.PositiveSmallIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class OnboardingChecklist(models.Model):
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='onboarding_checklists')
    item = models.CharField(max_length=120)
    completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)

class LeaveRequest(models.Model):
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='leave_requests')
    type = models.CharField(
        choices=[('vacation','Congés'),('sick','Maladie'),('maternity','Maternité'),('unpaid','Sans solde')],
        max_length=15
    )
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(choices=[('pending','En attente'),('approved','Approuvée'),('rejected','Refusée')], max_length=12, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

class Timesheet(models.Model):
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='timesheets')
    week_start = models.DateField()
    hours_worked = models.DecimalField(max_digits=5, decimal_places=2)
    submitted_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_timesheets')
    notes = models.TextField(blank=True)

class EmployeeDocument(models.Model):
    employee_record = models.ForeignKey(EmployeeRecord, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=120)
    file = models.FileField(upload_to='employee_docs/')
    description = models.TextField(blank=True)
    added_at = models.DateTimeField(auto_now_add=True)

class InternalNotification(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='notifications')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    message = models.TextField()
    target_roles = models.ManyToManyField(Role, blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    is_urgent = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    is_published = models.BooleanField(default=True)

# Expériences professionnelles du candidat
class WorkExperience(models.Model):
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='work_experiences')
    job_title = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)
    location = models.CharField(max_length=255, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)  # null si en cours
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.job_title} chez {self.company_name}"

# Formations / Diplômes du candidat
class Education(models.Model):
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='educations')
    school_name = models.CharField(max_length=255)
    degree = models.CharField(max_length=255, blank=True)
    field_of_study = models.CharField(max_length=255, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.degree} - {self.school_name}"

# Certifications éventuelles
class Certification(models.Model):
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='certifications')
    name = models.CharField(max_length=255)
    authority = models.CharField(max_length=255, blank=True)
    license_number = models.CharField(max_length=255, blank=True)
    date_obtained = models.DateField()
    expiration_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"Certification : {self.name}"

# Documents (CV, lettre de motivation, autres)
class CandidateDocument(models.Model):
    candidate = models.ForeignKey(CandidateProfile, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(
        max_length=50,
        choices=[('cv', 'CV'), ('cover_letter', 'Lettre de motivation'), ('other', 'Autre')]
    )
    file = models.FileField(upload_to='candidate_documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.document_type} de {self.candidate.user.email}"


# Notes et échanges sur la candidature
class ApplicationNote(models.Model):
    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)  # recruteur ou RH
    note = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

# Communications/messages entre recruteur et candidat (ex: questions, réponses, suivis)
class ApplicationMessage(models.Model):
    application = models.ForeignKey(JobApplication, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)  # Candidate or recruiter
    message = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)

#____________________PLATEFORME DE SERVICES & GESTION DES CONTRATS____________________#
#____________________FREELANCE & MATCHING MODELS____________________#

class ServicesTags(models.Model):
    tag = models.CharField(max_length=50)
    def __str__(self):
        return f"{self.tag}"

# Services offerts par l’entreprise
class Service(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='services')
    serviceCategory = models.ForeignKey(ServiceCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='services')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    price = models.PositiveIntegerField(null=True, blank=True)  # prix indicatif
    duration_minutes = models.PositiveIntegerField(null=True, blank=True)  # durée estimée
    thumbnail = models.ImageField(upload_to='service_thumbnails/', blank=True, null=True)
    images = models.ManyToManyField('ServicesPicture', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.company.name})"
    
class ServicesPicture(models.Model):
    image = models.ImageField(upload_to='service_pictures/')
    description = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.service.name}"
    
class ServiceLike(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='liked_services')
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='likes')
    liked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'service')

    def __str__(self):
        return f"{self.user.email} likes {self.service.name}"

# Prestataires de services (ServiceProviderProfile) avec compétences, catégories, localisation, tarifs, etc.
class ServiceProviderProfile(models.Model):
    """
    Extending existing profile with skills and service categories.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='provider_profile')
    company = models.ForeignKey('Company', on_delete=models.SET_NULL, null=True, blank=True, related_name='providers')
    skills = models.ManyToManyField(Skill, blank=True)
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
    services = models.ManyToManyField(Service, blank=True, related_name='providers')
    availability_status = models.CharField(max_length=20, choices=[('available', 'Available'), ('unavailable', 'Unavailable')], default='available')

    def __str__(self):
        return f"Provider: {self.user}"

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

    class Meta:
        unique_together = ('client_request', 'provider_profile')

    def __str__(self):
        return f"Match {self.client_request} - {self.provider_profile} : {self.score}"

class ProviderSkill(models.Model):
    provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='provider_skills')
    skill = models.ForeignKey(Skill, on_delete=models.CASCADE, related_name='provider_skills')
    level = models.CharField(
        max_length=20,
        choices=[('beginner','Débutant'), ('intermediate','Intermédiaire'), ('expert','Expert')],
        default='beginner'
    )
    class Meta:
        unique_together = ('provider', 'skill')

class ServiceRequest(models.Model):
    client = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='service_requests')
    company = models.ForeignKey('Company', on_delete=models.CASCADE, related_name='service_requests')
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

class ProviderReview(models.Model):
    contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rating = models.PositiveSmallIntegerField()
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ('contract', 'reviewer')

class ServiceMessage(models.Model):
    contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    message = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)


#_______________Gestion des paiements et comptes séquestres________________#


class EscrowAccount(models.Model):
    contract = models.OneToOneField(ServiceContract, on_delete=models.CASCADE, related_name='escrow_account')
    amount_held = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    is_released = models.BooleanField(default=False)
    release_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def release_payment(self):
        if not self.is_released:
            self.is_released = True
            self.release_date = timezone.now()
            self.save()

class PaymentTransaction(models.Model):
    escrow_account = models.ForeignKey(EscrowAccount, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_date = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255, blank=True)
    transaction_type = models.CharField(
        max_length=20,
        choices=[('deposit','Dépôt'), ('release','Libération'), ('refund','Remboursement')]
    )
    external_ref = models.CharField(max_length=255, blank=True)

class StatusHistory(models.Model):
    content_type = models.ForeignKey('contenttypes.ContentType', on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    # content_object = models.GenericForeignKey('content_type', 'object_id')
    old_status = models.CharField(max_length=50)
    new_status = models.CharField(max_length=50)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(auto_now_add=True)

class Dispute(models.Model):
    contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='disputes')
    opened_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    reason = models.TextField()
    status = models.CharField(
        choices=[('open','Ouvert'), ('resolved','Résolu'), ('closed','Fermé')],
        default='open', max_length=10
    )
    opened_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)

class Notification(models.Model):
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class AvailabilitySlot(models.Model):
    provider = models.ForeignKey(ServiceProviderProfile, on_delete=models.CASCADE, related_name='availability_slots')
    start_datetime = models.DateTimeField()
    end_datetime = models.DateTimeField()
    is_booked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class Invoice(models.Model):
    contract = models.ForeignKey(ServiceContract, on_delete=models.CASCADE, related_name='invoices')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    issued_at = models.DateField(auto_now_add=True)
    due_date = models.DateField()
    is_paid = models.BooleanField(default=False)
    payment_reference = models.CharField(max_length=255, blank=True)

#____________________ Website Content & Config Models ____________________#

class FAQEntry(models.Model):
    question = models.CharField(max_length=255)
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.question

class Patnership(models.Model):
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='partners_logos/')
    website = models.URLField(blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
class Testimonial(models.Model):
    author_name = models.CharField(max_length=255)
    author_title = models.CharField(max_length=255, blank=True)
    content = models.TextField()
    author_photo = models.ImageField(upload_to='testimonials_photos/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Testimonial by {self.author_name}"
    
class TrustedCompany(models.Model):
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='trusted_companies_logos/')
    website = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    

















# Ideas for AI integration workflow (outside models):

"""
1. Feature Extraction:
   - Extract skill vectors for providers and client requests.
   - Include location proximity, ratings, historical completed jobs.
   - Budget compatibility and remote work allowance.

2. Matching Algorithm:
   - Use classical scoring with weighted criteria or embed Machine Learning model.
   - Example: calculate cosine similarity between skill vectors.
   - Factor location using Haversine distance; factor ratings and budget match.

3. AI Model:
   - Train ML model on past successful matches and client feedback.
   - Input features: skills, ratings, location, budget, job categories.
   - Output: match confidence score.

4. Integration:
   - Run matching asynchronously (Celery task).
   - Store matches and notify clients/providers.

5. User Feedback:
   - Collect client acceptance/rejection to improve AI models.

"""


