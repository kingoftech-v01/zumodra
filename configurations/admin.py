from django.contrib import admin

# Register your models here.
# from django.contrib import admin
# from .models import (
#     ServiceCategory, Skill, Company, Site, CompanyProfile, Department, Role,
#     Service, Membership, ServiceProviderProfile, ClientRequest, Match,
#     CandidateProfile, JobPosition, Job, JobApplication, EmployeeRecord,
#     ContractDocument, Interview, InterviewNote, OnboardingChecklist, LeaveRequest,
#     Timesheet, EmployeeDocument, InternalNotification, WorkExperience, Education,
#     Certification, CandidateDocument, ApplicationNote, ApplicationMessage,
#     ProviderSkill, ServiceRequest, ServiceProposal, ServiceContract,
#     EscrowAccount, PaymentTransaction, ProviderReview, ServiceMessage,
#     StatusHistory, Dispute, Notification, AvailabilitySlot, Invoice
# )


# class SiteInline(admin.TabularInline):
#     model = Site
#     extra = 1

# class DepartmentInline(admin.TabularInline):
#     model = Department
#     extra = 1

# class CompanyProfileInline(admin.StackedInline):
#     model = CompanyProfile
#     extra = 0

# class ServiceInline(admin.TabularInline):
#     model = Service
#     extra = 1

# class MembershipInline(admin.TabularInline):
#     model = Membership
#     extra = 1

# class RoleInline(admin.TabularInline):
#     model = Role
#     extra = 1

# @admin.register(Company)
# class CompanyAdmin(admin.ModelAdmin):
#     list_display = ('name', 'industry', 'domain', 'created_at')
#     search_fields = ('name', 'domain', 'industry')
#     list_filter = ('industry',)
#     inlines = [SiteInline, CompanyProfileInline, ServiceInline]

# @admin.register(Site)
# class SiteAdmin(admin.ModelAdmin):
#     list_display = ('name', 'company', 'city', 'country', 'is_main_office')
#     list_filter = ('country', 'is_main_office')
#     search_fields = ('name', 'city', 'company__name')
#     ordering = ['company', 'is_main_office']

# @admin.register(CompanyProfile)
# class CompanyProfileAdmin(admin.ModelAdmin):
#     list_display = ('company', 'website', 'linkedin_url', 'twitter_url')
#     search_fields = ('company__name', 'website', 'linkedin_url')

# @admin.register(Department)
# class DepartmentAdmin(admin.ModelAdmin):
#     list_display = ('name', 'company')
#     list_filter = ('company',)
#     search_fields = ('name',)

# @admin.register(Role)
# class RoleAdmin(admin.ModelAdmin):
#     list_display = ('name', 'company', 'group')
#     list_filter = ('company',)
#     search_fields = ('name',)
#     raw_id_fields = ['group', 'permissions']

# @admin.register(Membership)
# class MembershipAdmin(admin.ModelAdmin):
#     list_display = ('user', 'company', 'department', 'role', 'job_title', 'is_active', 'created_at')
#     search_fields = ('user__email', 'company__company__name', 'department__name', 'role__name')
#     list_filter = ('is_active', 'role', 'department', 'company')

# @admin.register(ServiceCategory)
# class ServiceCategoryAdmin(admin.ModelAdmin):
#     list_display = ('name',)
#     search_fields = ('name',)

# @admin.register(Skill)
# class SkillAdmin(admin.ModelAdmin):
#     list_display = ('name', 'description', 'created_at')
#     search_fields = ('name',)
#     list_filter = ('created_at',)

# @admin.register(Service)
# class ServiceAdmin(admin.ModelAdmin):
#     list_display = ('name', 'company', 'serviceCategory', 'price', 'updated_at')
#     list_filter = ('company', 'serviceCategory')
#     search_fields = ('name', 'company__name', 'description')
#     ordering = ['-updated_at']

# @admin.register(ServiceProviderProfile)
# class ServiceProviderProfileAdmin(admin.ModelAdmin):
#     list_display = (
#         'user', 'company', 'hourly_rate', 'rating_avg', 'completed_jobs', 'total_reviews', 'last_active'
#     )
#     search_fields = ('user__email', 'company__name', 'bio')
#     list_filter = ('company',)
#     filter_horizontal = ('skills', 'categories')

# @admin.register(ClientRequest)
# class ClientRequestAdmin(admin.ModelAdmin):
#     list_display = ('client', 'service_category', 'budget_min', 'budget_max', 'remote_allowed', 'created_at')
#     search_fields = ('client__email', 'description')
#     list_filter = ('remote_allowed', 'created_at', 'service_category')
#     filter_horizontal = ('required_skills',)

# @admin.register(Match)
# class MatchAdmin(admin.ModelAdmin):
#     list_display = ('client_request', 'provider_profile', 'score', 'matched_at', 'viewed_by_client', 'accepted_by_client')
#     list_filter = ('matched_at', 'viewed_by_client', 'accepted_by_client')
#     search_fields = ('client_request__description', 'provider_profile__user__email')

# @admin.register(CandidateProfile)
# class CandidateProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'phone', 'created_at')
#     search_fields = ('user__email', 'bio', 'phone')

# @admin.register(JobPosition)
# class JobPositionAdmin(admin.ModelAdmin):
#     list_display = ('title', 'company', 'site', 'department', 'is_open', 'created_at')
#     search_fields = ('title', 'company__company__name')
#     list_filter = ('company', 'department', 'site', 'is_open')

# @admin.register(Job)
# class JobAdmin(admin.ModelAdmin):
#     list_display = ('title', 'company', 'position', 'salary_from', 'salary_to', 'is_active', 'posted_at')
#     list_filter = ('company', 'is_active')
#     search_fields = ('title', 'description', 'company__name')

# @admin.register(JobApplication)
# class JobApplicationAdmin(admin.ModelAdmin):
#     list_display = ('candidate', 'job', 'status', 'applied_at', 'updated_at')
#     list_filter = ('status', 'applied_at', 'job')
#     search_fields = ('candidate__user__email', 'job__title')

# @admin.register(EmployeeRecord)
# class EmployeeRecordAdmin(admin.ModelAdmin):
#     list_display = ('membership', 'hire_date', 'contract_type', 'salary', 'status')
#     list_filter = ('contract_type', 'status')
#     search_fields = ('membership__user__email', 'membership__company__company__name')

# @admin.register(ContractDocument)
# class ContractDocumentAdmin(admin.ModelAdmin):
#     list_display = ('employee_record', 'upload', 'signed_at', 'created_at')
#     search_fields = ('employee_record__membership__user__email', 'description')

# @admin.register(Interview)
# class InterviewAdmin(admin.ModelAdmin):
#     list_display = ('application', 'interviewer', 'interviewee', 'scheduled_at', 'status')
#     list_filter = ('status', 'scheduled_at', 'mode')
#     search_fields = ('application__candidate__user__email', 'interviewer__user__email')

# @admin.register(OnboardingChecklist)
# class OnboardingChecklistAdmin(admin.ModelAdmin):
#     list_display = ('employee_record', 'item', 'completed', 'completed_at')
#     list_filter = ('completed',)
#     search_fields = ('employee_record__membership__user__email', 'item')

# @admin.register(LeaveRequest)
# class LeaveRequestAdmin(admin.ModelAdmin):
#     list_display = ('employee_record', 'type', 'start_date', 'end_date', 'status', 'requested_at', 'reviewer')
#     list_filter = ('type', 'status')
#     search_fields = ('employee_record__membership__user__email', 'reason')

# @admin.register(Timesheet)
# class TimesheetAdmin(admin.ModelAdmin):
#     list_display = ('employee_record', 'week_start', 'hours_worked', 'submitted_at', 'approved', 'approved_at', 'approver')
#     list_filter = ('approved',)
#     search_fields = ('employee_record__membership__user__email', 'notes')

# @admin.register(EmployeeDocument)
# class EmployeeDocumentAdmin(admin.ModelAdmin):
#     list_display = ('employee_record', 'title', 'file', 'added_at')
#     search_fields = ('employee_record__membership__user__email', 'title')

# @admin.register(InternalNotification)
# class InternalNotificationAdmin(admin.ModelAdmin):
#     list_display = ('company', 'created_by', 'sent_at', 'is_urgent', 'is_published')
#     list_filter = ('is_urgent', 'is_read', 'is_archived', 'is_published')
#     search_fields = ('company__name', 'message')

# @admin.register(WorkExperience)
# class WorkExperienceAdmin(admin.ModelAdmin):
#     list_display = ('candidate', 'job_title', 'company_name', 'location', 'start_date', 'end_date')
#     search_fields = ('candidate__user__email', 'job_title', 'company_name')

# @admin.register(Education)
# class EducationAdmin(admin.ModelAdmin):
#     list_display = ('candidate', 'school_name', 'degree', 'field_of_study', 'start_date', 'end_date')
#     search_fields = ('candidate__user__email', 'school_name', 'degree', 'field_of_study')

# @admin.register(Certification)
# class CertificationAdmin(admin.ModelAdmin):
#     list_display = ('candidate', 'name', 'authority', 'license_number', 'date_obtained', 'expiration_date')
#     search_fields = ('candidate__user__email', 'name', 'authority', 'license_number')

# @admin.register(CandidateDocument)
# class CandidateDocumentAdmin(admin.ModelAdmin):
#     list_display = ('candidate', 'document_type', 'file', 'uploaded_at')
#     search_fields = ('candidate__user__email', 'document_type')

# @admin.register(ApplicationNote)
# class ApplicationNoteAdmin(admin.ModelAdmin):
#     list_display = ('application', 'author', 'created_at')
#     search_fields = ('application__candidate__user__email', 'author__email')

# @admin.register(ApplicationMessage)
# class ApplicationMessageAdmin(admin.ModelAdmin):
#     list_display = ('application', 'sender', 'sent_at')
#     search_fields = ('application__candidate__user__email', 'sender__email')

# @admin.register(ProviderSkill)
# class ProviderSkillAdmin(admin.ModelAdmin):
#     list_display = ('provider', 'skill', 'level')
#     list_filter = ('level',)

# @admin.register(ServiceRequest)
# class ServiceRequestAdmin(admin.ModelAdmin):
#     list_display = ('client', 'company', 'title', 'budget_min', 'budget_max', 'deadline', 'is_open')
#     list_filter = ('is_open', 'deadline', 'company')
#     search_fields = ('client__email', 'title', 'company__name')
#     filter_horizontal = ('required_skills',)

# @admin.register(ServiceProposal)
# class ServiceProposalAdmin(admin.ModelAdmin):
#     list_display = ('request', 'provider', 'proposed_rate', 'submitted_at', 'is_accepted')
#     list_filter = ('is_accepted',)
#     search_fields = ('request__title', 'provider__user__email')

# @admin.register(ServiceContract)
# class ServiceContractAdmin(admin.ModelAdmin):
#     list_display = ('request', 'provider', 'client', 'agreed_rate', 'agreed_deadline', 'status', 'created_at', 'updated_at')
#     list_filter = ('status',)
#     search_fields = ('request__title', 'provider__user__email', 'client__email')

# @admin.register(EscrowAccount)
# class EscrowAccountAdmin(admin.ModelAdmin):
#     list_display = ('contract', 'amount_held', 'is_released', 'release_date', 'created_at')
#     list_filter = ('is_released',)
#     search_fields = ('contract__provider__user__email', 'contract__client__email')

# @admin.register(PaymentTransaction)
# class PaymentTransactionAdmin(admin.ModelAdmin):
#     list_display = ('escrow_account', 'amount', 'transaction_date', 'transaction_type', 'external_ref')
#     list_filter = ('transaction_type',)
#     search_fields = ('escrow_account__contract__provider__user__email', 'external_ref')

# @admin.register(ProviderReview)
# class ProviderReviewAdmin(admin.ModelAdmin):
#     list_display = ('contract', 'reviewer', 'rating', 'created_at')
#     search_fields = ('contract__provider__user__email', 'reviewer__email')

# @admin.register(ServiceMessage)
# class ServiceMessageAdmin(admin.ModelAdmin):
#     list_display = ('contract', 'sender', 'sent_at')
#     search_fields = ('contract__provider__user__email', 'sender__email')

# @admin.register(StatusHistory)
# class StatusHistoryAdmin(admin.ModelAdmin):
#     list_display = ('content_type', 'object_id', 'old_status', 'new_status', 'changed_by', 'changed_at')
#     list_filter = ('old_status', 'new_status')

# @admin.register(Dispute)
# class DisputeAdmin(admin.ModelAdmin):
#     list_display = ('contract', 'opened_by', 'reason', 'status', 'opened_at', 'resolved_at')
#     list_filter = ('status',)
#     search_fields = ('contract__provider__user__email', 'opened_by__email')

# @admin.register(Notification)
# class NotificationAdmin(admin.ModelAdmin):
#     list_display = ('recipient', 'message', 'is_read', 'created_at')
#     list_filter = ('is_read',)
#     search_fields = ('recipient__email', 'message')

# @admin.register(AvailabilitySlot)
# class AvailabilitySlotAdmin(admin.ModelAdmin):
#     list_display = ('provider', 'start_datetime', 'end_datetime', 'is_booked', 'created_at')
#     list_filter = ('is_booked',)

# @admin.register(Invoice)
# class InvoiceAdmin(admin.ModelAdmin):
#     list_display = ('contract', 'amount', 'issued_at', 'due_date', 'is_paid', 'payment_reference')
#     list_filter = ('is_paid',)
#     search_fields = ('contract__provider__user__email', 'payment_reference')
