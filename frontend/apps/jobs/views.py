from django.views.generic import TemplateView


class JobListView(TemplateView):
    template_name = 'jobs/list_default.html'


class JobListView2(TemplateView):
    template_name = 'jobs/list_view.html'


class JobGridView(TemplateView):
    template_name = 'jobs/grid_view.html'


class JobMapGridView(TemplateView):
    template_name = 'jobs/map_grid_v1.html'


class JobMapGridView2(TemplateView):
    template_name = 'jobs/map_grid_v2.html'


class JobDetailView(TemplateView):
    template_name = 'jobs/detail_v1.html'


class JobDetailView2(TemplateView):
    template_name = 'jobs/detail_v2.html'
