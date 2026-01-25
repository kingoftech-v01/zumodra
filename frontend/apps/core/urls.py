from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('about/', views.AboutView.as_view(), name='about'),
    path('about-2/', views.About2View.as_view(), name='about2'),
    path('contact/', views.ContactView.as_view(), name='contact'),
    path('contact-2/', views.Contact2View.as_view(), name='contact2'),
    path('faqs/', views.FAQsView.as_view(), name='faqs'),
    path('pricing/', views.PricingView.as_view(), name='pricing'),
    path('become-buyer/', views.BecomeBuyerView.as_view(), name='become_buyer'),
    path('become-seller/', views.BecomeSellerView.as_view(), name='become_seller'),
]
