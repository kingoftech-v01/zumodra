from django.views.generic import TemplateView


class ServiceListView(TemplateView):
    template_name = 'services/list.html'


class ServiceMapView(TemplateView):
    template_name = 'services/map.html'


class ServiceDetailView(TemplateView):
    template_name = 'services/detail_v1.html'


class ServiceDetailView2(TemplateView):
    template_name = 'services/detail_v2.html'
