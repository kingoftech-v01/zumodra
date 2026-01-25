from django.views.generic import TemplateView


class AcceptableUsePolicyView(TemplateView):
    template_name = 'legal/acceptable-use-policy.html'


class CommunityGuidelinesView(TemplateView):
    template_name = 'legal/community-guidelines.html'


class CookiePolicyView(TemplateView):
    template_name = 'legal/cookie-policy.html'


class CopyrightDMCAView(TemplateView):
    template_name = 'legal/copyright-dmca.html'


class DisclaimerView(TemplateView):
    template_name = 'legal/disclaimer.html'


class DisputeResolutionView(TemplateView):
    template_name = 'legal/dispute-resolution.html'


class GDPRComplianceView(TemplateView):
    template_name = 'legal/gdpr-compliance.html'


class LegalNoticeView(TemplateView):
    template_name = 'legal/legal-notice.html'


class PaymentTermsView(TemplateView):
    template_name = 'legal/payment-terms.html'


class PrivacyPolicyView(TemplateView):
    template_name = 'legal/privacy-policy.html'


class RefundPolicyView(TemplateView):
    template_name = 'legal/refund-policy.html'


class ServiceAgreementView(TemplateView):
    template_name = 'legal/service-agreement.html'


class TermsOfUseView(TemplateView):
    template_name = 'legal/terms-of-use.html'
