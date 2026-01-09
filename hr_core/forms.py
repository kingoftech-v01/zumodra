"""
HR Core Forms - Human Resources Operations

This module provides forms for:
- Employee management
- Time-off requests
- Onboarding process
- Performance reviews
- Document management
- Compensation records
"""

from decimal import Decimal
from django import forms
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import (
    Employee,
    TimeOffType,
    TimeOffRequest,
    OnboardingChecklist,
    OnboardingTask,
    EmployeeOnboarding,
    OnboardingTaskProgress,
    DocumentTemplate,
    EmployeeDocument,
    Offboarding,
    PerformanceReview,
    EmployeeCompensation,
    TimeOffBalance,
    TimeOffBlackoutDate,
    SkillCategory,
    Skill,
    EmployeeSkill,
    Certification,
    EmployeeGoal,
)


class EmployeeForm(forms.ModelForm):
    """
    Form for creating and updating employee records.
    Handles employment details, position, and basic HR data.
    """

    class Meta:
        model = Employee
        fields = [
            'employee_id',
            'status',
            'employment_type',
            'job_title',
            'department',
            'manager',
            'team',
            'work_location',
            'hire_date',
            'start_date',
            'probation_end_date',
            'base_salary',
            'salary_currency',
            'pay_frequency',
            'emergency_contact_name',
            'emergency_contact_phone',
            'emergency_contact_relationship',
        ]
        widgets = {
            'employee_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('EMP-001'),
            }),
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'employment_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'job_title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Job Title'),
            }),
            'department': forms.Select(attrs={
                'class': 'form-select',
            }),
            'manager': forms.Select(attrs={
                'class': 'form-select',
            }),
            'team': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Team Name'),
            }),
            'work_location': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Office Location'),
            }),
            'hire_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'probation_end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'base_salary': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'salary_currency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'pay_frequency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'emergency_contact_name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Emergency Contact Name'),
            }),
            'emergency_contact_phone': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Emergency Contact Phone'),
            }),
            'emergency_contact_relationship': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Relationship'),
            }),
        }
        help_texts = {
            'employee_id': _('Unique identifier for this employee'),
            'probation_end_date': _('Leave blank if no probation period'),
            'base_salary': _('Annual base salary'),
        }

    def clean(self):
        """Validate date relationships."""
        cleaned_data = super().clean()
        hire_date = cleaned_data.get('hire_date')
        start_date = cleaned_data.get('start_date')
        probation_end_date = cleaned_data.get('probation_end_date')

        if start_date and hire_date and start_date < hire_date:
            raise ValidationError({
                'start_date': _('Start date cannot be before hire date.')
            })

        if probation_end_date and start_date and probation_end_date < start_date:
            raise ValidationError({
                'probation_end_date': _('Probation end date cannot be before start date.')
            })

        return cleaned_data


class EmployeeWorkAuthorizationForm(forms.ModelForm):
    """
    Form for managing employee work authorization details.
    Handles visa, work permit, and right to work verification.
    """

    class Meta:
        model = Employee
        fields = [
            'work_authorization_status',
            'visa_type',
            'visa_expiry',
            'work_permit_number',
            'work_permit_expiry',
            'right_to_work_verified',
            'right_to_work_verified_date',
        ]
        widgets = {
            'work_authorization_status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'visa_type': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Visa Type'),
            }),
            'visa_expiry': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'work_permit_number': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Work Permit Number'),
            }),
            'work_permit_expiry': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'right_to_work_verified': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'right_to_work_verified_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }


class TimeOffTypeForm(forms.ModelForm):
    """
    Form for managing time-off types.
    Configures accrual rates, policies, and limits.
    """

    class Meta:
        model = TimeOffType
        fields = [
            'name',
            'code',
            'description',
            'color',
            'is_accrued',
            'accrual_rate',
            'max_balance',
            'max_carryover',
            'requires_approval',
            'requires_documentation',
            'min_notice_days',
            'is_paid',
            'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Time Off Type Name'),
            }),
            'code': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('PTO, SICK, etc.'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'color': forms.TextInput(attrs={
                'class': 'form-input',
                'type': 'color',
            }),
            'is_accrued': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'accrual_rate': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'max_balance': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'max_carryover': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'requires_approval': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'requires_documentation': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'min_notice_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'is_paid': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'accrual_rate': _('Days accrued per pay period'),
            'max_balance': _('Maximum balance allowed (leave blank for no limit)'),
            'max_carryover': _('Maximum days to carry over to next year'),
            'min_notice_days': _('Minimum days notice required for requests'),
        }


class TimeOffRequestForm(forms.ModelForm):
    """
    Form for submitting time-off requests.
    Employees use this to request vacation, sick leave, etc.
    """

    class Meta:
        model = TimeOffRequest
        fields = [
            'time_off_type',
            'start_date',
            'end_date',
            'is_half_day',
            'half_day_period',
            'reason',
            'supporting_document',
        ]
        widgets = {
            'time_off_type': forms.Select(attrs={
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
            'is_half_day': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'half_day_period': forms.Select(attrs={
                'class': 'form-select',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Reason for time off request...'),
            }),
            'supporting_document': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png',
            }),
        }
        help_texts = {
            'is_half_day': _('Check if requesting only half a day'),
            'supporting_document': _('Attach documentation if required (medical note, etc.)'),
        }

    def clean(self):
        """Validate date range and calculate total days."""
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        is_half_day = cleaned_data.get('is_half_day')

        if start_date and end_date:
            if end_date < start_date:
                raise ValidationError({
                    'end_date': _('End date cannot be before start date.')
                })

            if start_date < timezone.now().date():
                raise ValidationError({
                    'start_date': _('Cannot request time off for past dates.')
                })

            # Calculate total days
            delta = (end_date - start_date).days + 1
            if is_half_day:
                cleaned_data['total_days'] = Decimal('0.5')
            else:
                cleaned_data['total_days'] = Decimal(str(delta))

        return cleaned_data

    def clean_supporting_document(self):
        """Validate file size."""
        doc = self.cleaned_data.get('supporting_document')
        if doc and hasattr(doc, 'size'):
            if doc.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(_('File must be less than 10MB.'))
        return doc


class TimeOffApprovalForm(forms.ModelForm):
    """
    Form for managers to approve/reject time-off requests.
    """

    class Meta:
        model = TimeOffRequest
        fields = [
            'status',
            'rejection_reason',
            'notes',
        ]
        widgets = {
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'rejection_reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
                'placeholder': _('Reason for rejection...'),
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
                'placeholder': _('Additional notes...'),
            }),
        }

    def clean(self):
        """Require rejection reason if rejecting."""
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        rejection_reason = cleaned_data.get('rejection_reason')

        if status == 'rejected' and not rejection_reason:
            raise ValidationError({
                'rejection_reason': _('Please provide a reason for rejection.')
            })
        return cleaned_data


class OnboardingChecklistForm(forms.ModelForm):
    """
    Form for creating onboarding checklist templates.
    """

    class Meta:
        model = OnboardingChecklist
        fields = [
            'name',
            'description',
            'employment_type',
            'department',
            'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Checklist Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'employment_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'department': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'employment_type': _('Leave blank to apply to all employment types'),
            'department': _('Leave blank to apply to all departments'),
        }


class OnboardingTaskForm(forms.ModelForm):
    """
    Form for adding tasks to an onboarding checklist.
    """

    class Meta:
        model = OnboardingTask
        fields = [
            'title',
            'description',
            'category',
            'order',
            'assigned_to_role',
            'due_days',
            'is_required',
            'requires_signature',
            'document_template',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Task Title'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'assigned_to_role': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('HR, Manager, IT, etc.'),
            }),
            'due_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'is_required': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'requires_signature': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'document_template': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'due_days': _('Number of days after employee start date'),
            'assigned_to_role': _('Who is responsible for this task'),
        }


class EmployeeOnboardingForm(forms.ModelForm):
    """
    Form for initiating employee onboarding.
    """

    class Meta:
        model = EmployeeOnboarding
        fields = [
            'checklist',
            'start_date',
            'target_completion_date',
            'notes',
        ]
        widgets = {
            'checklist': forms.Select(attrs={
                'class': 'form-select',
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'target_completion_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }


class OnboardingTaskProgressForm(forms.ModelForm):
    """
    Form for updating onboarding task progress.
    """

    class Meta:
        model = OnboardingTaskProgress
        fields = [
            'is_completed',
            'notes',
        ]
        widgets = {
            'is_completed': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
        }


class DocumentTemplateForm(forms.ModelForm):
    """
    Form for creating HR document templates.
    """

    class Meta:
        model = DocumentTemplate
        fields = [
            'name',
            'category',
            'description',
            'content',
            'placeholders',
            'requires_signature',
            'is_active',
            'version',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Template Name'),
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-textarea code-editor',
                'rows': 20,
            }),
            'placeholders': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
                'placeholder': _('["employee_name", "job_title", "start_date"]'),
            }),
            'requires_signature': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'version': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('1.0'),
            }),
        }
        help_texts = {
            'content': _('HTML template with placeholders like {{employee_name}}'),
            'placeholders': _('JSON array of available placeholder names'),
        }


class EmployeeDocumentForm(forms.ModelForm):
    """
    Form for uploading employee documents.
    """

    class Meta:
        model = EmployeeDocument
        fields = [
            'title',
            'category',
            'description',
            'file',
            'requires_signature',
            'expires_at',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Document Title'),
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'file': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.pdf,.doc,.docx,.xls,.xlsx,.jpg,.jpeg,.png',
            }),
            'requires_signature': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'expires_at': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
        }
        help_texts = {
            'file': _('Allowed formats: PDF, DOC, DOCX, XLS, XLSX, JPG, PNG. Max 10MB.'),
        }

    def clean_file(self):
        """Validate file size."""
        file = self.cleaned_data.get('file')
        if file and hasattr(file, 'size'):
            if file.size > 10 * 1024 * 1024:  # 10MB
                raise ValidationError(_('File must be less than 10MB.'))
        return file


class OffboardingForm(forms.ModelForm):
    """
    Form for initiating employee offboarding.
    """

    class Meta:
        model = Offboarding
        fields = [
            'separation_type',
            'reason',
            'notice_date',
            'last_working_day',
            'exit_interview_date',
            'severance_offered',
            'severance_amount',
            'pto_payout_days',
            'eligible_for_rehire',
            'rehire_notes',
        ]
        widgets = {
            'separation_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
            'notice_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'last_working_day': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'exit_interview_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'severance_offered': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'severance_amount': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'pto_payout_days': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'eligible_for_rehire': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'rehire_notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
        }

    def clean(self):
        """Validate date relationships."""
        cleaned_data = super().clean()
        notice_date = cleaned_data.get('notice_date')
        last_working_day = cleaned_data.get('last_working_day')

        if notice_date and last_working_day:
            if last_working_day < notice_date:
                raise ValidationError({
                    'last_working_day': _('Last working day cannot be before notice date.')
                })
        return cleaned_data


class OffboardingChecklistForm(forms.ModelForm):
    """
    Form for updating offboarding checklist items.
    """

    class Meta:
        model = Offboarding
        fields = [
            'knowledge_transfer_complete',
            'equipment_returned',
            'access_revoked',
            'final_paycheck_processed',
            'benefits_terminated',
            'exit_interview_completed',
            'exit_interview_notes',
        ]
        widgets = {
            'knowledge_transfer_complete': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'equipment_returned': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'access_revoked': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'final_paycheck_processed': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'benefits_terminated': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'exit_interview_completed': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'exit_interview_notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
            }),
        }


class PerformanceReviewForm(forms.ModelForm):
    """
    Form for creating and managing performance reviews.
    """

    class Meta:
        model = PerformanceReview
        fields = [
            'review_type',
            'review_period_start',
            'review_period_end',
            'overall_rating',
            'goals_met_percentage',
            'manager_feedback',
            'accomplishments',
            'areas_for_improvement',
            'goals_for_next_period',
            'promotion_recommended',
            'salary_increase_recommended',
            'salary_increase_percentage',
            'pip_recommended',
        ]
        widgets = {
            'review_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'review_period_start': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'review_period_end': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'overall_rating': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '1',
                'max': '5',
            }),
            'goals_met_percentage': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '100',
            }),
            'manager_feedback': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 5,
            }),
            'accomplishments': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'areas_for_improvement': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'goals_for_next_period': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'promotion_recommended': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'salary_increase_recommended': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'salary_increase_percentage': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'pip_recommended': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }
        help_texts = {
            'overall_rating': _('Rating from 1 (needs improvement) to 5 (exceptional)'),
            'pip_recommended': _('Recommend Performance Improvement Plan'),
        }


class SelfAssessmentForm(forms.ModelForm):
    """
    Form for employee self-assessment during performance review.
    """

    class Meta:
        model = PerformanceReview
        fields = [
            'self_assessment',
        ]
        widgets = {
            'self_assessment': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 10,
                'placeholder': _('Describe your accomplishments, challenges, and growth during this review period...'),
            }),
        }


class EmployeeCompensationForm(forms.ModelForm):
    """
    Form for recording compensation changes.
    """

    class Meta:
        model = EmployeeCompensation
        fields = [
            'effective_date',
            'base_salary',
            'currency',
            'pay_frequency',
            'bonus_target_percentage',
            'bonus_type',
            'commission_percentage',
            'equity_shares',
            'equity_vest_start',
            'equity_vest_end',
            'equity_cliff_months',
            'change_reason',
            'change_notes',
        ]
        widgets = {
            'effective_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'base_salary': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'currency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'pay_frequency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'bonus_target_percentage': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'bonus_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'commission_percentage': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'equity_shares': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'equity_vest_start': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'equity_vest_end': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'equity_cliff_months': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'change_reason': forms.Select(attrs={
                'class': 'form-select',
            }),
            'change_notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 3,
            }),
        }


class TimeOffBalanceForm(forms.ModelForm):
    """
    Form for adjusting time-off balances.
    """

    class Meta:
        model = TimeOffBalance
        fields = [
            'balance',
            'accrued_this_year',
            'used_this_year',
            'carried_over',
            'accrual_rate_override',
        ]
        widgets = {
            'balance': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
            }),
            'accrued_this_year': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
            }),
            'used_this_year': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
            }),
            'carried_over': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
            }),
            'accrual_rate_override': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
            }),
        }
        help_texts = {
            'accrual_rate_override': _('Leave blank to use default rate for this time-off type'),
        }


class TimeOffBlackoutDateForm(forms.ModelForm):
    """
    Form for creating time-off blackout periods.
    """

    class Meta:
        model = TimeOffBlackoutDate
        fields = [
            'name',
            'description',
            'start_date',
            'end_date',
            'applies_to_all',
            'departments',
            'restriction_type',
            'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Blackout Period Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'applies_to_all': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'departments': forms.SelectMultiple(attrs={
                'class': 'form-select',
            }),
            'restriction_type': forms.Select(attrs={
                'class': 'form-select',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class SkillCategoryForm(forms.ModelForm):
    """
    Form for managing skill categories.
    """

    class Meta:
        model = SkillCategory
        fields = ['name', 'description', 'order', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Category Name'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class SkillForm(forms.ModelForm):
    """
    Form for managing skills.
    """

    class Meta:
        model = Skill
        fields = ['name', 'category', 'description', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Skill Name'),
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
        }


class EmployeeSkillForm(forms.ModelForm):
    """
    Form for adding skills to an employee.
    """

    class Meta:
        model = EmployeeSkill
        fields = [
            'skill',
            'proficiency',
            'years_of_experience',
            'last_used_date',
            'is_primary',
            'notes',
        ]
        widgets = {
            'skill': forms.Select(attrs={
                'class': 'form-select',
            }),
            'proficiency': forms.Select(attrs={
                'class': 'form-select',
            }),
            'years_of_experience': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.1',
                'min': '0',
            }),
            'last_used_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'is_primary': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
        }


class CertificationForm(forms.ModelForm):
    """
    Form for adding employee certifications.
    """

    class Meta:
        model = Certification
        fields = [
            'name',
            'issuing_organization',
            'credential_id',
            'credential_url',
            'issue_date',
            'expiry_date',
            'certificate_file',
            'notes',
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Certification Name'),
            }),
            'issuing_organization': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Issuing Organization'),
            }),
            'credential_id': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Credential ID'),
            }),
            'credential_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': _('Verification URL'),
            }),
            'issue_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'expiry_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'certificate_file': forms.FileInput(attrs={
                'class': 'form-file',
                'accept': '.pdf,.jpg,.jpeg,.png',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 2,
            }),
        }


class EmployeeGoalForm(forms.ModelForm):
    """
    Form for creating and managing employee goals.
    """

    class Meta:
        model = EmployeeGoal
        fields = [
            'title',
            'description',
            'category',
            'priority',
            'start_date',
            'target_date',
            'weight',
            'performance_review',
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': _('Goal Title'),
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'rows': 4,
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
            }),
            'priority': forms.Select(attrs={
                'class': 'form-select',
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'target_date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date',
            }),
            'weight': forms.NumberInput(attrs={
                'class': 'form-input',
                'step': '0.01',
                'min': '0',
            }),
            'performance_review': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
        help_texts = {
            'weight': _('Weight of this goal in overall performance (default 1.0)'),
        }

    def clean(self):
        """Validate date relationships."""
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        target_date = cleaned_data.get('target_date')

        if start_date and target_date and target_date < start_date:
            raise ValidationError({
                'target_date': _('Target date cannot be before start date.')
            })
        return cleaned_data


class GoalProgressForm(forms.ModelForm):
    """
    Form for updating goal progress.
    """

    class Meta:
        model = EmployeeGoal
        fields = [
            'status',
            'progress_percentage',
        ]
        widgets = {
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'progress_percentage': forms.NumberInput(attrs={
                'class': 'form-input',
                'min': '0',
                'max': '100',
            }),
        }
