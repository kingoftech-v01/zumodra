from django.views.generic import TemplateView
from django.shortcuts import render


class HomeView(TemplateView):
    template_name = 'home/index.html'


class AboutView(TemplateView):
    template_name = 'about/about1.html'


class About2View(TemplateView):
    template_name = 'about/about2.html'


class ContactView(TemplateView):
    template_name = 'contact/contact1.html'


class Contact2View(TemplateView):
    template_name = 'contact/contact2.html'


class FAQsView(TemplateView):
    template_name = 'other/faqs.html'


class PricingView(TemplateView):
    template_name = 'other/pricing.html'


class BecomeBuyerView(TemplateView):
    template_name = 'other/become-buyer.html'


class BecomeSellerView(TemplateView):
    template_name = 'other/become-seller.html'


# Error handlers
def handler404(request, exception):
    return render(request, 'errors/404.html', status=404)


def handler500(request):
    return render(request, 'errors/500.html', status=500)
