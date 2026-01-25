from django.views.generic import TemplateView


class ProjectListView(TemplateView):
    template_name = 'projects/list.html'


class ProjectMapView(TemplateView):
    template_name = 'projects/map.html'


class ProjectDetailView(TemplateView):
    template_name = 'projects/detail_v1.html'


class ProjectDetailView2(TemplateView):
    template_name = 'projects/detail_v2.html'


class ProjectDetailView3(TemplateView):
    template_name = 'projects/detail_v3.html'
