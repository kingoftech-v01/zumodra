from django.urls import path, include
from .views import *

urlpatterns = [
    path('', chat_view, name='messages_index'),
]
