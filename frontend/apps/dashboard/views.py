from django.views.generic import TemplateView


# Main dashboard
class DashboardView(TemplateView):
    template_name = 'dashboard/dashboard.html'


# Work & Applications
class ActiveWorkView(TemplateView):
    template_name = 'dashboard/active_work.html'


class AppliedView(TemplateView):
    template_name = 'dashboard/applied.html'


# Alerts
class AddAlertView(TemplateView):
    template_name = 'dashboard/add_alert.html'


class AddAlertsCandidateView(TemplateView):
    template_name = 'dashboard/add_alerts_candidate.html'


class AlertsCandidateView(TemplateView):
    template_name = 'dashboard/alerts_candidate.html'


class AlertsCandidateDetailView(TemplateView):
    template_name = 'dashboard/alerts_candidate_detail.html'


class JobsAlertsView(TemplateView):
    template_name = 'dashboard/jobs_alerts.html'


class JobsAlertsDetailView(TemplateView):
    template_name = 'dashboard/jobs_alerts_detail.html'


# Applicants
class ApplicantsJobsView(TemplateView):
    template_name = 'dashboard/applicants_jobs.html'


class ApplicantsProjectsView(TemplateView):
    template_name = 'dashboard/applicants_projects.html'


# Billings & Finances
class BillingsView(TemplateView):
    template_name = 'dashboard/billings.html'


class EarningsView(TemplateView):
    template_name = 'dashboard/earnings.html'


class PayoutsView(TemplateView):
    template_name = 'dashboard/payouts.html'


# Bookmarks
class BookmarksView(TemplateView):
    template_name = 'dashboard/bookmarks.html'


# Services
class AddServiceView(TemplateView):
    template_name = 'dashboard/add_service.html'


class MyServicesView(TemplateView):
    template_name = 'dashboard/my_services.html'


class BoughtServicesView(TemplateView):
    template_name = 'dashboard/bought_services.html'


class ViewServiceDetailView(TemplateView):
    template_name = 'dashboard/view_service_detail.html'


class ServiceOrdersView(TemplateView):
    template_name = 'dashboard/service_orders.html'


class ServicesInqueueView(TemplateView):
    template_name = 'dashboard/services_inqueue.html'


# Profiles
class CandidatesProfileView(TemplateView):
    template_name = 'dashboard/candidates_profile.html'


class CandidatesProfileSettingView(TemplateView):
    template_name = 'dashboard/candidates_profile_setting.html'


class EmployersProfileView(TemplateView):
    template_name = 'dashboard/employers_profile.html'


class EmployersProfileSettingView(TemplateView):
    template_name = 'dashboard/employers_profile_setting.html'


# Packages
class ChoosePackageView(TemplateView):
    template_name = 'dashboard/choose_package.html'


class ChooseJobPackageView(TemplateView):
    template_name = 'dashboard/choose_job_package.html'


class ChooseProjectPackageView(TemplateView):
    template_name = 'dashboard/choose_project_package.html'


class CandidatesMyPackagesView(TemplateView):
    template_name = 'dashboard/candidates_my_packages.html'


class EmployersMyPackagesView(TemplateView):
    template_name = 'dashboard/employers_my_packages.html'


# Jobs management
class JobsView(TemplateView):
    template_name = 'dashboard/jobs.html'


class JobsViewApplicantsView(TemplateView):
    template_name = 'dashboard/jobs_view_applicants.html'


class SubmitJobsView(TemplateView):
    template_name = 'dashboard/submit_jobs.html'


# Projects management
class MyProjectsView(TemplateView):
    template_name = 'dashboard/my_projects.html'


class SubmitProjectsView(TemplateView):
    template_name = 'dashboard/submit_projects.html'


# Proposals
class ProposalsView(TemplateView):
    template_name = 'dashboard/proposals.html'


class ProposalsProjectsView(TemplateView):
    template_name = 'dashboard/proposals_projects.html'


class ViewProposalsProjectsView(TemplateView):
    template_name = 'dashboard/view_proposals_projects.html'


# Communication
class MessagesView(TemplateView):
    template_name = 'dashboard/messages.html'


class MeetingsView(TemplateView):
    template_name = 'dashboard/meetings.html'


# Account settings
class ChangePasswordsView(TemplateView):
    template_name = 'dashboard/change_passwords.html'


class DeleteProfileView(TemplateView):
    template_name = 'dashboard/delete_profile.html'
