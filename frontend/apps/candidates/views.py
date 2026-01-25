from django.views.generic import TemplateView


class CandidateListView(TemplateView):
    template_name = 'candidates/list.html'


class CandidateMapView(TemplateView):
    template_name = 'candidates/map.html'


class CandidateDetailView(TemplateView):
    template_name = 'candidates/detail_v1.html'


class CandidateDetailView2(TemplateView):
    template_name = 'candidates/detail_v2.html'
