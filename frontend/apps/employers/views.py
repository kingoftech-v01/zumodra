from django.views.generic import TemplateView


class EmployerListView(TemplateView):
    template_name = 'employers/list.html'


class EmployerMapView(TemplateView):
    template_name = 'employers/map.html'


class EmployerDetailView(TemplateView):
    template_name = 'employers/detail_v1.html'


class EmployerDetailView2(TemplateView):
    template_name = 'employers/detail_v2.html'
