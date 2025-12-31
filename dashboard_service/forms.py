"""
Dashboard Service Forms - DEPRECATED

This module is deprecated. All forms should be created in the `services` app.

MIGRATION NOTE:
- Create forms in `services.forms` instead
- This file re-exports models for backwards compatibility only
"""

import warnings

warnings.warn(
    "dashboard_service.forms is deprecated. "
    "Create forms in services.forms instead.",
    DeprecationWarning,
    stacklevel=2
)

from django import forms

# Import models from services (canonical location)
from services.models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,
    # Backwards compatibility aliases
    ServicesTag,
    ServicesPicture,
    ServiceProviderProfile,
    Match,
    ServiceRequest,
    ServiceComment,
    ServiceMessage,
)


# Form classes using canonical model names
class ServiceCategoryForm(forms.ModelForm):
    class Meta:
        model = ServiceCategory
        fields = '__all__'


class ServiceTagForm(forms.ModelForm):
    class Meta:
        model = ServiceTag
        fields = '__all__'


class ServiceImageForm(forms.ModelForm):
    class Meta:
        model = ServiceImage
        fields = '__all__'


class ProviderSkillForm(forms.ModelForm):
    class Meta:
        model = ProviderSkill
        fields = '__all__'


class ServiceProviderForm(forms.ModelForm):
    class Meta:
        model = ServiceProvider
        exclude = ['uuid', 'created_at', 'updated_at', 'last_active_at']


class ServiceForm(forms.ModelForm):
    class Meta:
        model = Service
        fields = '__all__'


class ServiceLikeForm(forms.ModelForm):
    class Meta:
        model = ServiceLike
        fields = '__all__'


class ClientRequestForm(forms.ModelForm):
    class Meta:
        model = ClientRequest
        fields = '__all__'


class ProviderMatchForm(forms.ModelForm):
    class Meta:
        model = ProviderMatch
        fields = '__all__'


class ServiceProposalForm(forms.ModelForm):
    class Meta:
        model = ServiceProposal
        fields = '__all__'


class ServiceContractForm(forms.ModelForm):
    class Meta:
        model = ServiceContract
        fields = '__all__'


class ServiceReviewForm(forms.ModelForm):
    class Meta:
        model = ServiceReview
        fields = '__all__'


class ContractMessageForm(forms.ModelForm):
    class Meta:
        model = ContractMessage
        fields = '__all__'


# Backwards compatibility aliases
ServicesTagForm = ServiceTagForm
ServicesPictureForm = ServiceImageForm
ServiceProviderProfileForm = ServiceProviderForm
MatchForm = ProviderMatchForm
ServiceRequestForm = ClientRequestForm
ServiceCommentForm = ServiceReviewForm
ServiceMessageForm = ContractMessageForm
