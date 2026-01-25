"""
API Serializers - Convert Django models to JSON
"""
from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from core_identity.models import CustomUser as User
from services.models import (
    Service, ServiceProvider, ServiceCategory,
    ClientRequest, ServiceProposal, ServiceContract,
    ServiceReview
)
from interviews.models import Appointment
from configurations.models import Skill, Company


# ==================== USER SERIALIZERS ====================

class UserSerializer(serializers.ModelSerializer):
    """Basic user information"""
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'date_joined']
        read_only_fields = ['id', 'date_joined']


class UserDetailSerializer(serializers.ModelSerializer):
    """Detailed user information with profile"""
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'phone_number', 'date_joined', 'is_active'
        ]
        read_only_fields = ['id', 'date_joined', 'is_active']


# ==================== SERVICE SERIALIZERS ====================

class ServiceCategorySerializer(serializers.ModelSerializer):
    """Service category"""
    class Meta:
        model = ServiceCategory
        fields = ['id', 'name', 'parent', 'description', 'created_at']


class SkillSerializer(serializers.ModelSerializer):
    """Skill serializer"""
    class Meta:
        model = Skill
        fields = ['id', 'name', 'description']


class ServiceProviderSerializer(serializers.ModelSerializer):
    """Service provider profile"""
    user = UserSerializer(read_only=True)
    categories = ServiceCategorySerializer(many=True, read_only=True)

    class Meta:
        model = ServiceProvider
        fields = [
            'uuid', 'user', 'bio', 'categories', 'rating_avg',
            'total_reviews', 'completed_jobs_count', 'hourly_rate',
            'address', 'city', 'country', 'availability_status',
            'is_verified', 'avatar', 'display_name'
        ]
        read_only_fields = ['uuid', 'rating_avg', 'total_reviews', 'completed_jobs_count']


class ServiceSerializer(serializers.ModelSerializer):
    """Service listing"""
    provider = ServiceProviderSerializer(read_only=True)
    category = ServiceCategorySerializer(read_only=True)  # source defaults to field name

    class Meta:
        model = Service
        fields = [
            'uuid', 'provider', 'category', 'name', 'description',
            'price', 'duration_days', 'created_at', 'updated_at'
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']


class ServiceDetailSerializer(ServiceSerializer):
    """Detailed service with comments"""
    comments_count = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()

    def get_comments_count(self, obj):
        return obj.provider.reviews.count()

    def get_average_rating(self, obj):
        comments = obj.provider.reviews.all()
        if comments:
            return sum(c.rating for c in comments) / len(comments)
        return 0

    class Meta(ServiceSerializer.Meta):
        fields = ServiceSerializer.Meta.fields + ['comments_count', 'average_rating']


class ClientRequestSerializer(serializers.ModelSerializer):
    """Service request"""
    client = UserSerializer(read_only=True)
    required_skills = SkillSerializer(many=True, read_only=True)

    class Meta:
        model = ClientRequest
        fields = [
            'uuid', 'client', 'required_skills', 'title', 'description',
            'budget_min', 'budget_max', 'deadline', 'created_at', 'status'
        ]
        read_only_fields = ['uuid', 'created_at']


class ServiceProposalSerializer(serializers.ModelSerializer):
    """Service proposal"""
    provider = ServiceProviderSerializer(read_only=True)
    client_request = ClientRequestSerializer(read_only=True)

    class Meta:
        model = ServiceProposal
        fields = [
            'id', 'client_request', 'provider', 'proposed_rate',
            'cover_letter', 'created_at', 'status'
        ]
        read_only_fields = ['id', 'created_at', 'status']


class ServiceContractSerializer(serializers.ModelSerializer):
    """Service contract"""
    provider = ServiceProviderSerializer(read_only=True)
    client = UserSerializer(read_only=True)

    class Meta:
        model = ServiceContract
        fields = [
            'id', 'provider', 'client', 'agreed_rate', 'agreed_deadline',
            'status', 'created_at', 'started_at', 'completed_at'
        ]
        read_only_fields = ['id', 'created_at', 'started_at', 'completed_at']


class ServiceReviewSerializer(serializers.ModelSerializer):
    """Service review/comment"""
    reviewer = UserSerializer(read_only=True)

    class Meta:
        model = ServiceReview
        fields = [
            'id', 'reviewer', 'content', 'rating',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# ==================== APPOINTMENT SERIALIZERS ====================

class AppointmentSerializer(serializers.ModelSerializer):
    """Appointment serializer"""
    client = UserSerializer(read_only=True)

    class Meta:
        model = Appointment
        fields = [
            'id', 'client', 'phone', 'address', 'want_reminder',
            'additional_info', 'paid', 'amount_to_pay',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# ==================== COMPANY SERIALIZERS ====================

class CompanySerializer(serializers.ModelSerializer):
    """Company serializer"""
    owner = UserSerializer(read_only=True)

    class Meta:
        model = Company
        fields = [
            'id', 'name', 'owner', 'description', 'website',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']
