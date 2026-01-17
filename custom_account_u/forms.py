from django import forms
from allauth.account.forms import SignupForm

class CustomSignupForm(SignupForm):
    first_name = forms.CharField(max_length=30, label="Prénom")
    last_name = forms.CharField(max_length=30, label="Nom")
    user_type = forms.ChoiceField(
        choices=[
            ('public', 'Public User'),
            ('company', 'Company'),
            ('freelancer', 'Freelancer'),
        ],
        widget=forms.HiddenInput(),
        initial='public',
        required=False,
    )

    def save(self, request):
        user = super(CustomSignupForm, self).save(request)
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.save()

        # Store user type in session for post-signup routing
        user_type = self.cleaned_data.get('user_type', 'public')
        request.session['selected_user_type'] = user_type

        return user


# ==================== FREELANCER ONBOARDING FORMS ====================

class FreelancerProfileForm(forms.Form):
    """
    Step 1 of freelancer onboarding: Professional profile information.
    """
    professional_title = forms.CharField(
        max_length=200,
        label='Professional Title',
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': 'e.g., Full-Stack Developer, UX Designer',
        }),
    )

    bio = forms.CharField(
        label='Bio',
        widget=forms.Textarea(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 py-3 rounded-lg',
            'placeholder': 'Tell clients about yourself, your experience, and what makes you unique...',
            'rows': 5,
        }),
    )

    skills = forms.CharField(
        label='Skills (comma-separated)',
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': 'Python, Django, React, Node.js, AWS',
        }),
        help_text='Enter your skills separated by commas',
    )

    hourly_rate_min = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        label='Minimum Hourly Rate (USD)',
        widget=forms.NumberInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': '50.00',
            'min': '0',
            'step': '0.01',
        }),
    )

    hourly_rate_max = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        label='Maximum Hourly Rate (USD)',
        widget=forms.NumberInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': '150.00',
            'min': '0',
            'step': '0.01',
        }),
    )

    available_for_work = forms.BooleanField(
        required=False,
        initial=True,
        label='Available for work now',
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
    )


class FreelancerPlanForm(forms.Form):
    """
    Step 2 of freelancer onboarding: Marketplace plan selection (optional).
    """
    plan_choice = forms.ChoiceField(
        label='Marketplace Plan',
        choices=[
            ('free', 'Free Plan - $0/month (15% platform fee)'),
            ('pro', 'Pro Plan - $29/month (10% platform fee)'),
        ],
        initial='free',
        widget=forms.RadioSelect(attrs={
            'class': 'form-radio',
        }),
    )


class StripeConnectForm(forms.Form):
    """
    Step 3 of freelancer onboarding: Stripe Connect setup.
    """
    setup_payments = forms.BooleanField(
        required=False,
        initial=True,
        label='Set up payment receiving now',
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox',
        }),
        help_text='Connect your bank account to receive payments from clients',
    )
