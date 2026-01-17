"""
Public Profile Setup View

Optional profile completion for public users after signup.
Allows them to skip and go straight to dashboard.
"""

from django.views.generic import FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django import forms


class PublicProfileSetupForm(forms.Form):
    """
    Optional profile fields for public users.
    """
    professional_title = forms.CharField(
        max_length=200,
        required=False,
        label='Professional Title',
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': 'e.g., Software Engineer, Product Manager',
        }),
    )

    skills = forms.CharField(
        required=False,
        label='Skills (comma-separated)',
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': 'Python, React, Marketing, Design',
        }),
    )

    location = forms.CharField(
        max_length=100,
        required=False,
        label='Location',
        widget=forms.TextInput(attrs={
            'class': 'form-control w-full mt-3 border border-line px-4 h-[50px] rounded-lg',
            'placeholder': 'San Francisco, CA',
        }),
    )


class PublicProfileSetupView(LoginRequiredMixin, FormView):
    """
    View for public users to optionally complete their profile.
    """
    template_name = 'custom_account_u/public_profile_setup.html'
    form_class = PublicProfileSetupForm
    success_url = reverse_lazy('frontend:dashboard:index')

    def get(self, request, *args, **kwargs):
        """
        Allow skipping profile setup via ?skip=1 query parameter.
        """
        if request.GET.get('skip'):
            return redirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        """
        Save profile data to PublicProfile.
        """
        from custom_account_u.models import PublicProfile

        # Get or create PublicProfile
        profile, created = PublicProfile.objects.get_or_create(
            user=self.request.user
        )

        # Update fields
        if form.cleaned_data.get('professional_title'):
            profile.professional_title = form.cleaned_data['professional_title']

        if form.cleaned_data.get('skills'):
            # Convert comma-separated string to list
            skills_list = [
                skill.strip()
                for skill in form.cleaned_data['skills'].split(',')
                if skill.strip()
            ]
            profile.skills = skills_list

        if form.cleaned_data.get('location'):
            profile.location = form.cleaned_data['location']

        profile.profile_visibility = 'PUBLIC'
        profile.save()

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        """
        Add context for template.
        """
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Complete Your Profile (Optional)'
        context['can_skip'] = True
        return context
