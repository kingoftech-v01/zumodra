"""
Accounts Frontend Template Views.

Template-based views for account management, verification flows, and trust.
Uses Django templates with HTMX for dynamic interactions.
"""

from django.views.generic import TemplateView, FormView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django import forms

from .models import (
    KYCVerification, EmploymentVerification, EducationVerification,
    TrustScore, UserProfile, CandidateCV, StudentProfile
)
from .tasks import submit_kyc_to_provider, send_employment_verification_email


# ==================== FORMS ====================

class KYCVerificationForm(forms.ModelForm):
    """Form for starting KYC verification."""

    class Meta:
        model = KYCVerification
        fields = [
            'verification_type', 'level', 'document_type',
            'document_country', 'document_expiry'
        ]
        widgets = {
            'verification_type': forms.Select(attrs={
                'class': 'form-select',
                'hx-trigger': 'change',
            }),
            'level': forms.Select(attrs={'class': 'form-select'}),
            'document_type': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., passport, driver_license, id_card'
            }),
            'document_country': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., CA, US, FR'
            }),
            'document_expiry': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
        }


class EmploymentVerificationForm(forms.ModelForm):
    """Form for adding employment history."""

    class Meta:
        model = EmploymentVerification
        fields = [
            'company_name', 'job_title', 'start_date', 'end_date',
            'is_current', 'employment_type', 'description',
            'hr_contact_email', 'hr_contact_name', 'hr_contact_phone',
            'company_domain'
        ]
        widgets = {
            'company_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Company name'
            }),
            'job_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Job title'
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
            'is_current': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
                'hx-trigger': 'change',
                'hx-swap': 'none',
            }),
            'employment_type': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': 'Brief description of your role'
            }),
            'hr_contact_email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': 'hr@company.com'
            }),
            'hr_contact_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'HR contact name'
            }),
            'hr_contact_phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Phone number'
            }),
            'company_domain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'company.com'
            }),
        }


class EducationVerificationForm(forms.ModelForm):
    """Form for adding education history."""

    class Meta:
        model = EducationVerification
        fields = [
            'institution_name', 'institution_type', 'degree_type',
            'field_of_study', 'start_date', 'end_date', 'is_current',
            'graduated', 'gpa', 'honors', 'registrar_email',
            'institution_domain', 'student_id'
        ]
        widgets = {
            'institution_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'University/College name'
            }),
            'institution_type': forms.Select(attrs={'class': 'form-select'}),
            'degree_type': forms.Select(attrs={'class': 'form-select'}),
            'field_of_study': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., Computer Science'
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
            'is_current': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'graduated': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'gpa': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
                'max': '4.0',
                'placeholder': '3.50'
            }),
            'honors': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., Cum Laude'
            }),
            'registrar_email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': 'registrar@university.edu'
            }),
            'institution_domain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'university.edu'
            }),
            'student_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Student ID'
            }),
        }


class EmploymentVerificationResponseForm(forms.Form):
    """Form for HR to respond to employment verification."""

    dates_confirmed = forms.BooleanField(
        required=False,
        label=_("Dates are accurate"),
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'})
    )
    title_confirmed = forms.BooleanField(
        required=False,
        label=_("Job title is accurate"),
        widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'})
    )
    eligible_for_rehire = forms.ChoiceField(
        required=False,
        label=_("Eligible for rehire?"),
        choices=[
            ('', 'Prefer not to answer'),
            ('yes', 'Yes'),
            ('no', 'No'),
            ('with_conditions', 'With conditions'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    performance_rating = forms.ChoiceField(
        required=False,
        label=_("Overall performance"),
        choices=[
            ('', 'Prefer not to answer'),
            ('excellent', 'Excellent'),
            ('good', 'Good'),
            ('satisfactory', 'Satisfactory'),
            ('needs_improvement', 'Needs Improvement'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    verifier_name = forms.CharField(
        max_length=255,
        label=_("Your name"),
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Your full name'
        })
    )
    verifier_email = forms.EmailField(
        label=_("Your email"),
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'your.email@company.com'
        })
    )
    notes = forms.CharField(
        required=False,
        label=_("Additional notes"),
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': 'Any additional information...'
        })
    )


# ==================== VERIFICATION DASHBOARD ====================

class VerificationDashboardView(LoginRequiredMixin, TemplateView):
    """Main verification dashboard showing all verification statuses."""

    template_name = 'accounts/verification/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Get or create trust score
        trust_score, _ = TrustScore.objects.get_or_create(
            user=user,
            defaults={'entity_type': TrustScore.EntityType.CANDIDATE}
        )

        # Get verification records
        kyc_verifications = KYCVerification.objects.filter(user=user).order_by('-created_at')
        employment_verifications = EmploymentVerification.objects.filter(user=user).order_by('-start_date')
        education_verifications = EducationVerification.objects.filter(user=user).order_by('-end_date')

        # Calculate verification stats
        kyc_verified = kyc_verifications.filter(
            status=KYCVerification.VerificationStatus.VERIFIED
        ).exists()

        emp_total = employment_verifications.count()
        emp_verified = employment_verifications.filter(
            status=EmploymentVerification.VerificationStatus.VERIFIED
        ).count()

        edu_total = education_verifications.count()
        edu_verified = education_verifications.filter(
            status=EducationVerification.VerificationStatus.VERIFIED
        ).count()

        context.update({
            'trust_score': trust_score,
            'kyc_verifications': kyc_verifications[:5],
            'employment_verifications': employment_verifications[:10],
            'education_verifications': education_verifications[:10],
            'kyc_verified': kyc_verified,
            'emp_total': emp_total,
            'emp_verified': emp_verified,
            'edu_total': edu_total,
            'edu_verified': edu_verified,
            'career_progress': (
                ((emp_verified + edu_verified) / max(emp_total + edu_total, 1)) * 100
            ) if (emp_total + edu_total) > 0 else 0,
        })

        return context


# ==================== KYC VERIFICATION VIEWS ====================

class KYCStartView(LoginRequiredMixin, FormView):
    """Start KYC verification process."""

    template_name = 'accounts/verification/kyc_start.html'
    form_class = KYCVerificationForm

    def form_valid(self, form):
        verification = form.save(commit=False)
        verification.user = self.request.user
        verification.save()

        # Queue the verification task
        submit_kyc_to_provider.delay(verification.id)

        messages.success(
            self.request,
            _("Your identity verification has been submitted. You'll be notified when it's complete.")
        )

        return redirect('frontend:accounts:verification-dashboard')


class KYCStatusView(LoginRequiredMixin, TemplateView):
    """View KYC verification status."""

    template_name = 'accounts/verification/kyc_status.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uuid = kwargs.get('uuid')

        verification = get_object_or_404(
            KYCVerification,
            uuid=uuid,
            user=self.request.user
        )

        context['verification'] = verification
        return context


class KYCListView(LoginRequiredMixin, TemplateView):
    """List all KYC verifications for user."""

    template_name = 'accounts/verification/kyc_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['verifications'] = KYCVerification.objects.filter(
            user=self.request.user
        ).order_by('-created_at')
        return context


# ==================== EMPLOYMENT VERIFICATION VIEWS ====================

class EmploymentListView(LoginRequiredMixin, TemplateView):
    """List all employment records."""

    template_name = 'accounts/verification/employment_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['verifications'] = EmploymentVerification.objects.filter(
            user=self.request.user
        ).order_by('-start_date')
        return context


class EmploymentAddView(LoginRequiredMixin, FormView):
    """Add new employment record."""

    template_name = 'accounts/verification/employment_add.html'
    form_class = EmploymentVerificationForm

    def form_valid(self, form):
        verification = form.save(commit=False)
        verification.user = self.request.user
        verification.save()

        messages.success(
            self.request,
            _("Employment record added successfully.")
        )

        return redirect('frontend:accounts:employment-list')


class EmploymentDetailView(LoginRequiredMixin, TemplateView):
    """View employment record details."""

    template_name = 'accounts/verification/employment_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uuid = kwargs.get('uuid')

        verification = get_object_or_404(
            EmploymentVerification,
            uuid=uuid,
            user=self.request.user
        )

        context['verification'] = verification
        return context


class EmploymentRequestVerificationView(LoginRequiredMixin, View):
    """Send verification request to HR contact."""

    def post(self, request, uuid):
        verification = get_object_or_404(
            EmploymentVerification,
            uuid=uuid,
            user=request.user
        )

        if not verification.hr_contact_email:
            messages.error(
                request,
                _("Please add an HR contact email before requesting verification.")
            )
            return redirect('frontend:accounts:employment-detail', uuid=uuid)

        # Queue email task
        send_employment_verification_email.delay(verification.id)

        messages.success(
            request,
            _("Verification request sent to %(email)s") % {
                'email': verification.hr_contact_email
            }
        )

        return redirect('frontend:accounts:employment-detail', uuid=uuid)


class EmploymentVerificationResponseView(View):
    """Public view for HR to respond to verification request."""

    template_name = 'accounts/verification/employment_response.html'

    def get(self, request, token):
        verification = get_object_or_404(
            EmploymentVerification,
            verification_token=token
        )

        # Check if token is expired
        if verification.token_expires_at and verification.token_expires_at < timezone.now():
            return render(request, 'accounts/verification/token_expired.html', {
                'verification': verification
            })

        # Check if already verified
        if verification.status == EmploymentVerification.VerificationStatus.VERIFIED:
            return render(request, 'accounts/verification/already_verified.html', {
                'verification': verification
            })

        form = EmploymentVerificationResponseForm()

        return render(request, self.template_name, {
            'verification': verification,
            'form': form,
        })

    def post(self, request, token):
        verification = get_object_or_404(
            EmploymentVerification,
            verification_token=token
        )

        # Check if token is expired
        if verification.token_expires_at and verification.token_expires_at < timezone.now():
            return render(request, 'accounts/verification/token_expired.html', {
                'verification': verification
            })

        form = EmploymentVerificationResponseForm(request.POST)

        if form.is_valid():
            # Build response data
            response_data = {
                'dates_confirmed': form.cleaned_data.get('dates_confirmed'),
                'title_confirmed': form.cleaned_data.get('title_confirmed'),
                'eligible_for_rehire': form.cleaned_data.get('eligible_for_rehire'),
                'performance_rating': form.cleaned_data.get('performance_rating'),
                'verifier_name': form.cleaned_data.get('verifier_name'),
                'verifier_email': form.cleaned_data.get('verifier_email'),
                'notes': form.cleaned_data.get('notes'),
                'submitted_at': timezone.now().isoformat(),
            }

            # Mark as verified
            verification.mark_verified(response_data)

            return render(request, 'accounts/verification/employment_response_success.html', {
                'verification': verification
            })

        return render(request, self.template_name, {
            'verification': verification,
            'form': form,
        })


# ==================== EDUCATION VERIFICATION VIEWS ====================

class EducationListView(LoginRequiredMixin, TemplateView):
    """List all education records."""

    template_name = 'accounts/verification/education_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['verifications'] = EducationVerification.objects.filter(
            user=self.request.user
        ).order_by('-end_date')
        return context


class EducationAddView(LoginRequiredMixin, FormView):
    """Add new education record."""

    template_name = 'accounts/verification/education_add.html'
    form_class = EducationVerificationForm

    def form_valid(self, form):
        verification = form.save(commit=False)
        verification.user = self.request.user
        verification.save()

        messages.success(
            self.request,
            _("Education record added successfully.")
        )

        return redirect('frontend:accounts:education-list')


class EducationDetailView(LoginRequiredMixin, TemplateView):
    """View education record details."""

    template_name = 'accounts/verification/education_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uuid = kwargs.get('uuid')

        verification = get_object_or_404(
            EducationVerification,
            uuid=uuid,
            user=self.request.user
        )

        context['verification'] = verification
        return context


class EducationUploadTranscriptView(LoginRequiredMixin, View):
    """Upload transcript for education verification."""

    def post(self, request, uuid):
        verification = get_object_or_404(
            EducationVerification,
            uuid=uuid,
            user=request.user
        )

        if 'transcript' in request.FILES:
            verification.transcript_file = request.FILES['transcript']
            verification.verification_method = EducationVerification.VerificationMethod.TRANSCRIPT
            verification.status = EducationVerification.VerificationStatus.PENDING
            verification.save()

            messages.success(
                request,
                _("Transcript uploaded successfully. Our team will review it shortly.")
            )
        else:
            messages.error(request, _("Please select a file to upload."))

        return redirect('frontend:accounts:education-detail', uuid=uuid)


# ==================== TRUST SCORE VIEW ====================

class TrustScoreView(LoginRequiredMixin, TemplateView):
    """View detailed trust score breakdown."""

    template_name = 'accounts/verification/trust_score.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        trust_score, created = TrustScore.objects.get_or_create(
            user=user,
            defaults={'entity_type': TrustScore.EntityType.CANDIDATE}
        )

        if created:
            # Initialize component scores
            trust_score.update_identity_score()
            trust_score.update_career_score()
            trust_score.update_review_score()
            trust_score.update_dispute_score()
            trust_score.calculate_overall_score()

        context['trust_score'] = trust_score
        context['trust_explanation'] = trust_score.trust_explanation

        return context


# ==================== HTMX PARTIAL VIEWS ====================

class HTMXVerificationCardView(LoginRequiredMixin, View):
    """HTMX endpoint for refreshing verification cards."""

    def get(self, request, verification_type, uuid):
        user = request.user

        if verification_type == 'kyc':
            verification = get_object_or_404(KYCVerification, uuid=uuid, user=user)
            template = 'accounts/verification/partials/kyc_card.html'
        elif verification_type == 'employment':
            verification = get_object_or_404(EmploymentVerification, uuid=uuid, user=user)
            template = 'accounts/verification/partials/employment_card.html'
        elif verification_type == 'education':
            verification = get_object_or_404(EducationVerification, uuid=uuid, user=user)
            template = 'accounts/verification/partials/education_card.html'
        else:
            return HttpResponse(status=404)

        return render(request, template, {'verification': verification})


class HTMXTrustScoreBadgeView(LoginRequiredMixin, View):
    """HTMX endpoint for refreshing trust score badge."""

    def get(self, request):
        trust_score, _ = TrustScore.objects.get_or_create(
            user=request.user,
            defaults={'entity_type': TrustScore.EntityType.CANDIDATE}
        )

        return render(request, 'accounts/verification/partials/trust_badge.html', {
            'trust_score': trust_score
        })
