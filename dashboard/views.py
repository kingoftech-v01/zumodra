from django.shortcuts import render

# Create your views here.

def dashboard_view(request):
    return render(request, 'dashboard.html')

def bookmarks_view(request):
    return render(request, 'bookmarks.html')

from django.shortcuts import render

def candidates_active_work(request):
    return render(request, 'candidates-active-work.html')

def candidates_applied(request):
    return render(request, 'candidates-applied.html')

def candidates_choose_package(request):
    return render(request, 'candidates-choose-package.html')

def candidates_default(request):
    return render(request, 'candidates-default.html')

def candidates_detail1(request):
    return render(request, 'candidates-detail1.html')

def candidates_detail2(request):
    return render(request, 'candidates-detail2.html')

def candidates_earnings(request):
    return render(request, 'candidates-earnings.html')

def candidates_fullwidth_grid(request):
    return render(request, 'candidates-fullwidth-grid.html')

def candidates_fullwidth_list(request):
    return render(request, 'candidates-fullwidth-list.html')

def candidates_grid(request):
    return render(request, 'candidates-grid.html')

def candidates_half_map_grid(request):
    return render(request, 'candidates-half-map-grid.html')

def candidates_half_map_list(request):
    return render(request, 'candidates-half-map-list.html')

def candidates_list(request):
    return render(request, 'candidates-list.html')

def payouts(request):
    return render(request, 'payouts.html')

def candidates_proposals(request):
    return render(request, 'candidates-proposals.html')

def candidates_sidebar_grid(request):
    return render(request, 'candidates-sidebar-grid.html')

def candidates_sidebar_list(request):
    return render(request, 'candidates-sidebar-list.html')

def candidates_top_map_grid(request):
    return render(request, 'candidates-top-map-grid.html')

def candidates_top_map_list(request):
    return render(request, 'candidates-top-map-list.html')

def employers_applicants_jobs(request):
    return render(request, 'employers-applicants-jobs.html')

def employers_billings(request):
    return render(request, 'employers-billings.html')

def employers_choose_job_package(request):
    return render(request, 'employers-choose-job-package.html')

def employers_choose_project_package(request):
    return render(request, 'employers-choose-project-package.html')

def employers_default(request):
    return render(request, 'employers-default.html')

def employers_detail1(request):
    return render(request, 'employers-detail1.html')

def employers_detail2(request):
    return render(request, 'employers-detail2.html')

def employers_fullwidth(request):
    return render(request, 'employers-fullwidth.html')

def employers_grid(request):
    return render(request, 'employers-grid.html')

def employers_half_map_grid(request):
    return render(request, 'employers-half-map-grid.html')

def employers_half_map_list(request):
    return render(request, 'employers-half-map-list.html')

def employers_list(request):
    return render(request, 'employers-list.html')

def meetings(request):
    return render(request, 'meetings.html')

def messages(request):
    return render(request, 'messages.html')

def employers_my_projects(request):
    return render(request, 'employers-my-projects.html')

def employers_proposals_projects(request):
    return render(request, 'employers-proposals-projects.html')

def employers_sidebar_grid_2cols(request):
    return render(request, 'employers-sidebar-grid-2cols.html')

def employers_sidebar_grid_3cols(request):
    return render(request, 'employers-sidebar-grid-3cols.html')

def employers_sidebar_list(request):
    return render(request, 'employers-sidebar-list.html')

def employers_submit_projects(request):
    return render(request, 'employers-submit-projects.html')

def employers_top_map_grid(request):
    return render(request, 'employers-top-map-grid.html')

def employers_top_map_list(request):
    return render(request, 'employers-top-map-list.html')

def employers_view_proposals_projects(request):
    return render(request, 'employers-view-proposals-projects.html')

def employers_view_service_detail(request):
    return render(request, 'employers-view-service-detail.html')
