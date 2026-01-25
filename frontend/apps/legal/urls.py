from django.urls import path
from . import views

app_name = 'legal'

urlpatterns = [
    path('acceptable-use-policy/', views.AcceptableUsePolicyView.as_view(), name='acceptable_use_policy'),
    path('community-guidelines/', views.CommunityGuidelinesView.as_view(), name='community_guidelines'),
    path('cookie-policy/', views.CookiePolicyView.as_view(), name='cookie_policy'),
    path('copyright-dmca/', views.CopyrightDMCAView.as_view(), name='copyright_dmca'),
    path('disclaimer/', views.DisclaimerView.as_view(), name='disclaimer'),
    path('dispute-resolution/', views.DisputeResolutionView.as_view(), name='dispute_resolution'),
    path('gdpr-compliance/', views.GDPRComplianceView.as_view(), name='gdpr_compliance'),
    path('notice/', views.LegalNoticeView.as_view(), name='legal_notice'),
    path('payment-terms/', views.PaymentTermsView.as_view(), name='payment_terms'),
    path('privacy-policy/', views.PrivacyPolicyView.as_view(), name='privacy_policy'),
    path('refund-policy/', views.RefundPolicyView.as_view(), name='refund_policy'),
    path('service-agreement/', views.ServiceAgreementView.as_view(), name='service_agreement'),
    path('terms-of-use/', views.TermsOfUseView.as_view(), name='terms_of_use'),
]
