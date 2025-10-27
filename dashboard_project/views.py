from django.shortcuts import render
from .models import *
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404

# Create your views here.
def browse_project(request):
    projects_list_query = Project.objects.all()
    project_tags = ProjectTag.objects.all()
    project_categories = ProjectCategory.objects.all()
    project_providers = ProjectProviderProfile.objects.all()

    paginator = Paginator(projects_list_query, 10)
    page_number = request.GET.get('page')
    projects = paginator.get_page(page_number)

    request = request.GET.get('request')

    if request:
        projects_list_query = Project.objects.filter(name__icontains=request)

    context = {
        'projects': projects,
        'project_tags': project_tags,
        'project_categories': project_categories,
        'project_providers': project_providers,
    }
    return render(request, 'dashboard/browse-project.html', context)


def browse_project_detail(request, project_uuid):
    project = get_object_or_404(Project, uuid=project_uuid)
    context = {
        'project': project,
    }
    return render(request, 'dashboard/browse-project-detail.html')