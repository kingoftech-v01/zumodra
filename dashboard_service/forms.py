from django.forms import ModelForm
from .models import *
from django import forms
from .models import (
    ServiceCategory, ServicesTag, ServicesPicture, ProviderSkill,
    ServiceProviderProfile, Service, ServiceLike, ClientRequest,
    Match, ServiceRequest, ServiceProposal, ServiceContract,
    ServiceComment, ServiceMessage
)
from django.core.mail import send_mail

# class serviceForm(ModelForm):
#     class Meta:
#         model = service
#         fields = '__all__'


#     def save(self, commit=True):
#         service = super(serviceForm, self).save(commit=False)
#         if commit:
#             service.save()
#         return service



# Catégories de services
class ServiceCategoryForm(forms.ModelForm):
    class Meta:
        model = ServiceCategory
        fields = '__all__'


class ServicesTagForm(forms.ModelForm):
    class Meta:
        model = ServicesTag
        fields = '__all__'


class ServicesPictureForm(forms.ModelForm):
    class Meta:
        model = ServicesPicture
        fields = '__all__'


class ProviderSkillForm(forms.ModelForm):
    class Meta:
        model = ProviderSkill
        fields = '__all__'


class ServiceProviderProfileForm(forms.ModelForm):
    class Meta:
        model = ServiceProviderProfile
        exclude = ['uuid', 'created_at', 'updated_at', 'last_active', 'entity_name']


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


class MatchForm(forms.ModelForm):
    class Meta:
        model = Match
        fields = '__all__'


class ServiceRequestForm(forms.ModelForm):
    class Meta:
        model = ServiceRequest
        fields = '__all__'


class ServiceProposalForm(forms.ModelForm):
    class Meta:
        model = ServiceProposal
        fields = '__all__'


class ServiceContractForm(forms.ModelForm):
    class Meta:
        model = ServiceContract
        fields = '__all__'


class ServiceCommentForm(forms.ModelForm):
    class Meta:
        model = ServiceComment
        fields = '__all__'


class ServiceMessageForm(forms.ModelForm):
    class Meta:
        model = ServiceMessage
        fields = '__all__'
