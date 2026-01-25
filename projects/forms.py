"""
Projects Forms - Django forms for creating/editing projects.

This module provides ModelForms for:
- Project creation and editing
- Proposal submission
- Milestone management
- Deliverable uploads
- Review submission

All forms include validation, help text, and widget customization.
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import (
    Project,
    ProjectCategory,
    ProjectProvider,
    ProjectProposal,
    ProjectMilestone,
    ProjectDeliverable,
    ProjectReview,
    ProjectContract
)


# ============================================================================
# PROJECT FORMS
# ============================================================================

class ProjectForm(forms.ModelForm):
    """
    Form for creating and editing projects.

    Includes all essential fields for project posting.
    Used in frontend HTML views for project management.
    """

    class Meta:
        model = Project
        fields = [
            'title',
            'description',
            'short_description',
            'category',
            'required_skills',
            'experience_level',
            'start_date',
            'end_date',
            'estimated_duration_weeks',
            'deadline',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'deliverables',
            'location_type',
            'location_city',
            'location_country',
            'contact_email',
            'contact_person',
            'max_proposals',
            'proposal_deadline',
        ]
        widgets = {
            'description': forms.Textarea(attrs={
                'rows': 8,
                'placeholder': _('Describe the project goals, requirements, and expectations...')
            }),
            'short_description': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': _('Brief summary for listings (max 500 characters)')
            }),
            'required_skills': forms.TextInput(attrs={
                'placeholder': _('Python, Django, React, etc. (comma-separated)')
            }),
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
            'deadline': forms.DateInput(attrs={'type': 'date'}),
            'proposal_deadline': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'deliverables': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': _('List expected deliverables (one per line or JSON)')
            }),
        }
        help_texts = {
            'budget_min': _('Minimum budget in selected currency'),
            'budget_max': _('Maximum budget (leave blank for fixed price)'),
            'max_proposals': _('Maximum number of proposals to accept (default: 20)'),
        }

    def clean(self):
        """Validate cross-field constraints."""
        cleaned_data = super().clean()

        # Validate dates
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        deadline = cleaned_data.get('deadline')

        if start_date and end_date:
            if end_date <= start_date:
                raise ValidationError({
                    'end_date': _('End date must be after start date')
                })

        if deadline and deadline < timezone.now().date():
            raise ValidationError({
                'deadline': _('Deadline cannot be in the past')
            })

        # Validate budget
        budget_min = cleaned_data.get('budget_min')
        budget_max = cleaned_data.get('budget_max')

        if budget_min and budget_max:
            if budget_max < budget_min:
                raise ValidationError({
                    'budget_max': _('Maximum budget must be greater than minimum')
                })

        return cleaned_data


class ProjectFilterForm(forms.Form):
    """
    Form for filtering project listings.

    Used in list views for search and filtering.
    """

    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': _('Search projects...'),
            'class': 'search-input'
        })
    )

    category = forms.ModelChoiceField(
        queryset=ProjectCategory.objects.all(),
        required=False,
        empty_label=_('All Categories')
    )

    status = forms.ChoiceField(
        choices=[('', _('All Status'))] + list(Project.Status.choices),
        required=False
    )

    budget_type = forms.ChoiceField(
        choices=[('', _('Any Budget Type'))] + list(Project.BudgetType.choices),
        required=False
    )

    experience_level = forms.ChoiceField(
        choices=[('', _('Any Level'))] + list(Project.ExperienceLevel.choices),
        required=False
    )

    location_type = forms.ChoiceField(
        choices=[('', _('Any Location'))] + list(Project.LocationType.choices),
        required=False
    )

    sort_by = forms.ChoiceField(
        choices=[
            ('-created_at', _('Newest First')),
            ('created_at', _('Oldest First')),
            ('-published_at', _('Recently Published')),
            ('budget_max', _('Budget: Low to High')),
            ('-budget_max', _('Budget: High to Low')),
            ('deadline', _('Deadline: Soonest')),
        ],
        required=False,
        initial='-created_at'
    )


# ============================================================================
# PROPOSAL FORMS
# ============================================================================

class ProjectProposalForm(forms.ModelForm):
    """
    Form for submitting project proposals.

    Providers use this to bid on projects.
    """

    class Meta:
        model = ProjectProposal
        fields = [
            'cover_letter',
            'approach',
            'proposed_budget',
            'budget_currency',
            'proposed_duration_weeks',
            'proposed_start_date',
            'proposed_completion_date',
            'proposed_milestones',
            'portfolio_links',
        ]
        widgets = {
            'cover_letter': forms.Textarea(attrs={
                'rows': 6,
                'placeholder': _('Explain why you are perfect for this project...')
            }),
            'approach': forms.Textarea(attrs={
                'rows': 8,
                'placeholder': _('Describe your proposed methodology and approach...')
            }),
            'proposed_start_date': forms.DateInput(attrs={'type': 'date'}),
            'proposed_completion_date': forms.DateInput(attrs={'type': 'date'}),
            'proposed_milestones': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': _('Proposed milestones (JSON or one per line)')
            }),
            'portfolio_links': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': _('Links to relevant portfolio examples')
            }),
        }

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.project = project

        # Set budget currency from project if creating new proposal
        if project and not self.instance.pk:
            self.fields['budget_currency'].initial = project.budget_currency

    def clean(self):
        """Validate proposal constraints."""
        cleaned_data = super().clean()

        # Validate dates
        start_date = cleaned_data.get('proposed_start_date')
        completion_date = cleaned_data.get('proposed_completion_date')

        if start_date and completion_date:
            if completion_date <= start_date:
                raise ValidationError({
                    'proposed_completion_date': _('Completion date must be after start date')
                })

        # Validate budget matches project budget type
        if self.project:
            proposed_budget = cleaned_data.get('proposed_budget')
            if self.project.budget_min and proposed_budget:
                if proposed_budget < self.project.budget_min:
                    raise ValidationError({
                        'proposed_budget': _(
                            f'Budget must be at least {self.project.budget_min} {self.project.budget_currency}'
                        )
                    })

        return cleaned_data


# ============================================================================
# MILESTONE FORMS
# ============================================================================

class ProjectMilestoneForm(forms.ModelForm):
    """
    Form for creating and editing project milestones.

    Used by clients when setting up milestone-based projects.
    """

    class Meta:
        model = ProjectMilestone
        fields = [
            'title',
            'description',
            'order',
            'deliverables',
            'amount',
            'currency',
            'due_date',
        ]
        widgets = {
            'description': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': _('Describe milestone requirements...')
            }),
            'deliverables': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': _('Expected deliverables for this milestone')
            }),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def clean_due_date(self):
        """Ensure due date is not in the past."""
        due_date = self.cleaned_data.get('due_date')
        if due_date and due_date < timezone.now().date():
            raise ValidationError(_('Due date cannot be in the past'))
        return due_date


# ============================================================================
# DELIVERABLE FORMS
# ============================================================================

class ProjectDeliverableForm(forms.ModelForm):
    """
    Form for uploading project deliverables.

    Providers use this to submit work for review.
    """

    class Meta:
        model = ProjectDeliverable
        fields = [
            'title',
            'description',
            'file_url',
            'file_name',
            'file_size',
            'file_type',
        ]
        widgets = {
            'description': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': _('Describe the deliverable...')
            }),
        }


# ============================================================================
# REVIEW FORMS
# ============================================================================

class ProjectReviewForm(forms.ModelForm):
    """
    Form for submitting project reviews.

    Both clients and providers use this to review each other.
    """

    class Meta:
        model = ProjectReview
        fields = [
            'rating',
            'communication_rating',
            'quality_rating',
            'timeliness_rating',
            'professionalism_rating',
            'title',
            'review',
            'is_public',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'placeholder': _('Summary of your experience')
            }),
            'review': forms.Textarea(attrs={
                'rows': 6,
                'placeholder': _('Share your detailed experience...')
            }),
            'rating': forms.RadioSelect(),
            'communication_rating': forms.RadioSelect(),
            'quality_rating': forms.RadioSelect(),
            'timeliness_rating': forms.RadioSelect(),
            'professionalism_rating': forms.RadioSelect(),
        }
        labels = {
            'rating': _('Overall Rating'),
            'communication_rating': _('Communication'),
            'quality_rating': _('Quality of Work'),
            'timeliness_rating': _('Timeliness'),
            'professionalism_rating': _('Professionalism'),
        }

    def clean_rating(self):
        """Validate rating is between 1 and 5."""
        rating = self.cleaned_data.get('rating')
        if rating < 1 or rating > 5:
            raise ValidationError(_('Rating must be between 1 and 5'))
        return rating
