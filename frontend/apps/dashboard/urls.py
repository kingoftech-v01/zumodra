from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Main dashboard
    path('', views.DashboardView.as_view(), name='home'),

    # Active work & applications
    path('active-work/', views.ActiveWorkView.as_view(), name='active_work'),
    path('applied/', views.AppliedView.as_view(), name='applied'),

    # Alerts
    path('add-alert/', views.AddAlertView.as_view(), name='add_alert'),
    path('add-alerts-candidate/', views.AddAlertsCandidateView.as_view(), name='add_alerts_candidate'),
    path('alerts-candidate/', views.AlertsCandidateView.as_view(), name='alerts_candidate'),
    path('alerts-candidate-detail/', views.AlertsCandidateDetailView.as_view(), name='alerts_candidate_detail'),
    path('jobs-alerts/', views.JobsAlertsView.as_view(), name='jobs_alerts'),
    path('jobs-alerts-detail/', views.JobsAlertsDetailView.as_view(), name='jobs_alerts_detail'),

    # Applicants
    path('applicants-jobs/', views.ApplicantsJobsView.as_view(), name='applicants_jobs'),
    path('applicants-projects/', views.ApplicantsProjectsView.as_view(), name='applicants_projects'),

    # Billings & Finances
    path('billings/', views.BillingsView.as_view(), name='billings'),
    path('earnings/', views.EarningsView.as_view(), name='earnings'),
    path('payouts/', views.PayoutsView.as_view(), name='payouts'),

    # Bookmarks
    path('bookmarks/', views.BookmarksView.as_view(), name='bookmarks'),

    # Services
    path('add-service/', views.AddServiceView.as_view(), name='add_service'),
    path('my-services/', views.MyServicesView.as_view(), name='my_services'),
    path('bought-services/', views.BoughtServicesView.as_view(), name='bought_services'),
    path('view-service-detail/', views.ViewServiceDetailView.as_view(), name='view_service_detail'),
    path('service-orders/', views.ServiceOrdersView.as_view(), name='service_orders'),
    path('services-inqueue/', views.ServicesInqueueView.as_view(), name='services_inqueue'),

    # Profile pages
    path('candidates-profile/', views.CandidatesProfileView.as_view(), name='candidates_profile'),
    path('candidates-profile-setting/', views.CandidatesProfileSettingView.as_view(), name='candidates_profile_setting'),
    path('employers-profile/', views.EmployersProfileView.as_view(), name='employers_profile'),
    path('employers-profile-setting/', views.EmployersProfileSettingView.as_view(), name='employers_profile_setting'),

    # Packages
    path('choose-package/', views.ChoosePackageView.as_view(), name='choose_package'),
    path('choose-job-package/', views.ChooseJobPackageView.as_view(), name='choose_job_package'),
    path('choose-project-package/', views.ChooseProjectPackageView.as_view(), name='choose_project_package'),
    path('candidates-my-packages/', views.CandidatesMyPackagesView.as_view(), name='candidates_my_packages'),
    path('employers-my-packages/', views.EmployersMyPackagesView.as_view(), name='employers_my_packages'),

    # Jobs management
    path('jobs/', views.JobsView.as_view(), name='jobs'),
    path('jobs-view-applicants/', views.JobsViewApplicantsView.as_view(), name='jobs_view_applicants'),
    path('submit-jobs/', views.SubmitJobsView.as_view(), name='submit_jobs'),

    # Projects management
    path('my-projects/', views.MyProjectsView.as_view(), name='my_projects'),
    path('submit-projects/', views.SubmitProjectsView.as_view(), name='submit_projects'),

    # Proposals
    path('proposals/', views.ProposalsView.as_view(), name='proposals'),
    path('proposals-projects/', views.ProposalsProjectsView.as_view(), name='proposals_projects'),
    path('view-proposals-projects/', views.ViewProposalsProjectsView.as_view(), name='view_proposals_projects'),

    # Communication
    path('messages/', views.MessagesView.as_view(), name='messages'),
    path('meetings/', views.MeetingsView.as_view(), name='meetings'),

    # Account settings
    path('change-passwords/', views.ChangePasswordsView.as_view(), name='change_passwords'),
    path('delete-profile/', views.DeleteProfileView.as_view(), name='delete_profile'),
]
