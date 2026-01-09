"""
Configurations Forms - Core Taxonomy & Company Management

This module provides forms for:
- Skill management
- Company and organization structure
- FAQ and testimonials
- Website content management
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import (
    Skill,
    Company,
    Site,
    CompanyProfile,
    Department,
    Role,
    Membership,
    FAQEntry,
    Partnership,
    Testimonial,
    TrustedCompany,
    Job,
    JobPosition,
    EmployeeRecord,
    LeaveRequest,
    Timesheet,
)


class SkillForm(forms.ModelForm):
    """
    Form for creating and editing skills in the taxonomy.
    """

    class Meta:
        model = Skill
        fields = [
            'name',
            'slug',
            'description',
            'category',
            'is_verified',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Skill Name'),
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('skill-slug (auto-generated if blank)'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Skill description...'),
            }),
            'category': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Technical, Soft Skills, etc.'),
            }),
            'is_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'slug': _('URL-friendly identifier (auto-generated from name if left blank)'),
            'is_verified': _('Mark as admin-verified skill'),
        }


class CompanyForm(forms.ModelForm):
    """
    Form for creating and managing companies.
    """

    class Meta:
        model = Company
        fields = [
            'name',
            'slug',
            'description',
            'domain',
            'industry',
            'logo',
            'website',
            'employee_count',
            'founded_year',
            'is_verified',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'slug': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('company-slug'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Company description...'),
            }),
            'domain': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('company.com'),
            }),
            'industry': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Technology, Healthcare, etc.'),
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://company.com'),
            }),
            'employee_count': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'founded_year': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1800',
                'max': '2100',
            }),
            'is_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class SiteForm(forms.ModelForm):
    """
    Form for managing company sites/locations.
    """

    class Meta:
        model = Site
        fields = [
            'name',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'phone',
            'email',
            'established_date',
            'number_of_employees',
            'is_main_office',
            'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Site/Location Name'),
            }),
            'address': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Street Address'),
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('City'),
            }),
            'state': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('State/Province'),
            }),
            'postal_code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Postal Code'),
            }),
            'country': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Country'),
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('+1 (555) 123-4567'),
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input',
                'placeholder': _('site@company.com'),
            }),
            'established_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'number_of_employees': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
            }),
            'is_main_office': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class CompanyProfileForm(forms.ModelForm):
    """
    Form for extended company profile information.
    """

    class Meta:
        model = CompanyProfile
        fields = [
            'description',
            'website',
            'linkedin_url',
            'twitter_url',
            'facebook_url',
            'instagram_url',
            'culture_description',
            'benefits_description',
        ]
        widgets = {
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://company.com'),
            }),
            'linkedin_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://linkedin.com/company/...'),
            }),
            'twitter_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://twitter.com/...'),
            }),
            'facebook_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://facebook.com/...'),
            }),
            'instagram_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://instagram.com/...'),
            }),
            'culture_description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Describe your company culture...'),
            }),
            'benefits_description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Describe employee benefits...'),
            }),
        }


class DepartmentForm(forms.ModelForm):
    """
    Form for managing departments.
    """

    class Meta:
        model = Department
        fields = [
            'name',
            'description',
            'manager',
            'parent',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Department Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'manager': forms.Select(attrs={
                'class': 'form-select',
            }),
            'parent': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'parent': _('Parent department for hierarchy'),
        }


class RoleForm(forms.ModelForm):
    """
    Form for managing business roles.
    """

    class Meta:
        model = Role
        fields = [
            'name',
            'description',
            'group',
            'permissions',
            'is_default',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Role Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'group': forms.Select(attrs={
                'class': 'form-select',
            }),
            'permissions': forms.SelectMultiple(attrs={
                'class': 'form-select',
                'size': '10',
            }),
            'is_default': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'is_default': _('Default role assigned to new members'),
        }


class MembershipForm(forms.ModelForm):
    """
    Form for managing user-company memberships.
    """

    class Meta:
        model = Membership
        fields = [
            'user',
            'department',
            'role',
            'job_title',
            'is_active',
        ]
        widgets = {
            'user': forms.Select(attrs={
                'class': 'form-select',
            }),
            'department': forms.Select(attrs={
                'class': 'form-select',
            }),
            'role': forms.Select(attrs={
                'class': 'form-select',
            }),
            'job_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Job Title'),
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class FAQEntryForm(forms.ModelForm):
    """
    Form for creating and editing FAQ entries.
    """

    class Meta:
        model = FAQEntry
        fields = [
            'question',
            'answer',
            'category',
            'sort_order',
            'is_published',
        ]
        widgets = {
            'question': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Question'),
            }),
            'answer': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': _('Answer...'),
            }),
            'category': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('General, Pricing, Technical, etc.'),
            }),
            'sort_order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'is_published': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class PartnershipForm(forms.ModelForm):
    """
    Form for managing partnerships.
    """

    class Meta:
        model = Partnership
        fields = [
            'name',
            'logo',
            'website',
            'description',
            'is_featured',
            'sort_order',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Partner Name'),
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://partner.com'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'is_featured': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'sort_order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
        }


class TestimonialForm(forms.ModelForm):
    """
    Form for creating and editing testimonials.
    """

    class Meta:
        model = Testimonial
        fields = [
            'author_name',
            'author_title',
            'author_company',
            'content',
            'author_photo',
            'rating',
            'is_featured',
            'is_published',
        ]
        widgets = {
            'author_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Author Name'),
            }),
            'author_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Job Title'),
            }),
            'author_company': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': _('Testimonial content...'),
            }),
            'author_photo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'rating': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
                'max': '5',
            }),
            'is_featured': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_published': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }

    def clean_rating(self):
        """Validate rating is between 1 and 5."""
        rating = self.cleaned_data.get('rating')
        if rating and (rating < 1 or rating > 5):
            raise ValidationError(_('Rating must be between 1 and 5.'))
        return rating


class TrustedCompanyForm(forms.ModelForm):
    """
    Form for managing trusted company logos.
    """

    class Meta:
        model = TrustedCompany
        fields = [
            'name',
            'logo',
            'website',
            'sort_order',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Company Name'),
            }),
            'logo': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': 'image/*',
            }),
            'website': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('https://company.com'),
            }),
            'sort_order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
        }


class JobForm(forms.ModelForm):
    """
    Form for creating job listings.
    """

    class Meta:
        model = Job
        fields = [
            'company',
            'position',
            'title',
            'description',
            'requirements',
            'salary_from',
            'salary_to',
            'currency',
            'is_active',
            'closes_at',
        ]
        widgets = {
            'company': forms.Select(attrs={
                'class': 'form-select',
            }),
            'position': forms.Select(attrs={
                'class': 'form-select',
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Job Title'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 6,
                'placeholder': _('Job description...'),
            }),
            'requirements': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
                'placeholder': _('Job requirements...'),
            }),
            'salary_from': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'salary_to': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'closes_at': forms.DateTimeInput(attrs={
                'class': 'form-input',
                'type': 'datetime-local',
            }),
        }

    def clean(self):
        """Validate salary range."""
        cleaned_data = super().clean()
        salary_from = cleaned_data.get('salary_from')
        salary_to = cleaned_data.get('salary_to')

        if salary_from and salary_to and salary_from > salary_to:
            raise ValidationError({
                'salary_to': _('Maximum salary cannot be less than minimum salary.')
            })
        return cleaned_data


class JobPositionForm(forms.ModelForm):
    """
    Form for creating job position templates.
    """

    class Meta:
        model = JobPosition
        fields = [
            'company',
            'site',
            'department',
            'title',
            'description',
            'is_open',
        ]
        widgets = {
            'company': forms.Select(attrs={
                'class': 'form-select',
            }),
            'site': forms.Select(attrs={
                'class': 'form-select',
            }),
            'department': forms.Select(attrs={
                'class': 'form-select',
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Position Title'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'is_open': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class EmployeeRecordForm(forms.ModelForm):
    """
    Form for managing employee records.
    """

    class Meta:
        model = EmployeeRecord
        fields = [
            'employee_id',
            'hire_date',
            'contract_type',
            'salary',
            'currency',
            'status',
            'termination_date',
            'termination_reason',
            'notes',
        ]
        widgets = {
            'employee_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('EMP-001'),
            }),
            'hire_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'contract_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'salary': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'termination_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'termination_reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }


class LeaveRequestForm(forms.ModelForm):
    """
    Form for submitting leave requests.
    """

    class Meta:
        model = LeaveRequest
        fields = [
            'leave_type',
            'start_date',
            'end_date',
            'reason',
        ]
        widgets = {
            'leave_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Reason for leave...'),
            }),
        }

    def clean(self):
        """Validate date range."""
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if start_date and end_date and end_date < start_date:
            raise ValidationError({
                'end_date': _('End date cannot be before start date.')
            })
        return cleaned_data


class TimesheetForm(forms.ModelForm):
    """
    Form for submitting timesheets.
    """

    class Meta:
        model = Timesheet
        fields = [
            'week_start',
            'hours_worked',
            'notes',
        ]
        widgets = {
            'week_start': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'hours_worked': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.25',
                'min': '0',
                'max': '168',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }

    def clean_hours_worked(self):
        """Validate hours are reasonable."""
        hours = self.cleaned_data.get('hours_worked')
        if hours and hours > 168:  # Maximum hours in a week
            raise ValidationError(_('Hours worked cannot exceed 168 per week.'))
        return hours
