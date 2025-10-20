from django.shortcuts import render
from configurations.models import *
from django.core.paginator import paginator
from django.shortcuts import get_object_or_404

# Create your views here.


def index(request):
    return render(request, 'dashboard/index.html')


def browse_project(request):
    return render(request, 'dashboard/browse-project.html')


def browse_project_detail(request, project_uuid):
    return render(request, 'dashboard/browse-project-detail.html')


def browse_service(request):
    service_categories = ServiceCategory.objects.all()
    services_list_query = Service.objects.all()
    service_providers = ServiceProviderProfile.objects.all()
    service_tags = ServiceTag.objects.all()

    paginator = Paginator(services_list_query, 10)
    page_number = request.GET.get('page')
    services = paginator.get_page(page_number)

    request = request.GET.get('request')

    if request:
        service_categories = ServiceCategory.objects.filter(name__icontains=request)

    context = {
        'service_categories': service_categories,
        'services': services,
        'service_providers': service_providers,
        'service_tags': service_tags,
    }

    return render(request, 'dashboard/browse-service.html', context)


def browse_service_detail(request, service_uuid):
    # service = Service.objects.get(uuid=service_uuid)
    service = get_object_or_404(Service, uuid=service_uuid)
    

    context = {
        'service': service,
    }

    return render(request, 'dashboard/browse-service-detail.html', context)