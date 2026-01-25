"""
Signup Type Selection View

Allows users to choose their account type before completing signup:
- Public User (free, browsing only)
- Company (paid, needs tenant workspace)
- Freelancer (paid, marketplace + Stripe Connect)
"""

from django.views.generic import TemplateView
from django.shortcuts import redirect
from django.urls import reverse


class SignupTypeSelectionView(TemplateView):
    """
    Step 0 of signup: User selects their account type.

    This view presents three options and stores the selection in session,
    then redirects to the standard allauth signup form.
    """
    template_name = 'account/signup_type_selection.html'

    def post(self, request, *args, **kwargs):
        """
        Handle user type selection.
        """
        user_type = request.POST.get('user_type', 'public')

        # Validate user_type
        if user_type not in ['public', 'company', 'freelancer']:
            user_type = 'public'

        # Store selection in session
        request.session['selected_user_type'] = user_type

        # Redirect to signup form
        return redirect('account_signup')

    def get_context_data(self, **kwargs):
        """
        Add context for template.
        """
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Choose Your Account Type'
        return context
