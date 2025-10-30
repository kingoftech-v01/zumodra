from django.urls import path, include
from .views import *

urlpatterns = [
    path('idenfy/kyc/', start_kyc, name='start_kyc'),
    path('webhooks/idenfy/verification-update', idenfy_webhook, name='idenfy_webhook'),
]
