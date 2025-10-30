from django.urls import path, include
from .views import *

urlpatterns = [
    path('', chat_view, name='messages_index'),
]

from django.contrib import admin
from django.urls import path
from .views import *

urlpatterns = [
    path ('', chat_view, name='dashboard'),
]
