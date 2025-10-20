from django.urls import path
from .views import *

urlpatterns = [
    path('', blog_default, name='blog_default'),
    path('post-detail/<str:slug>', blog_post_detail, name='blog_post_detail'),
]