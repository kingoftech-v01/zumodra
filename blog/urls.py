from django.urls import path
from .views import *

urlpatterns = [
    path('posts/', blog_default, name='blog_main'),
    path('post-detail/<str:slug>', blog_post_detail, name='blog_post_detail'),
]