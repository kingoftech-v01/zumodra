"""
API Serializers - Convert Django models to JSON
"""
from rest_framework import serializers
from custom_account_u.models import CustomUser as User
from services.models import (
    DService, DServiceProviderProfile, DServiceCategory,
    DServiceRequest, DServiceProposal, DServiceContract,
    DServiceComment
)
from appointment.models import Appointment
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

class DServiceCategorySerializer(serializers.ModelSerializer):
    """Service category"""
    class Meta:
        model = DServiceCategory
        fields = ['id', 'name', 'parent', 'description', 'created_at']


class SkillSerializer(serializers.ModelSerializer):
    """Skill serializer"""
    class Meta:
        model = Skill
        fields = ['id', 'name', 'description']


class DServiceProviderProfileSerializer(serializers.ModelSerializer):
    """Service provider profile"""
    user = UserSerializer(read_only=True)
    categories = DServiceCategorySerializer(many=True, read_only=True)

    class Meta:
        model = DServiceProviderProfile
        fields = [
            'uuid', 'user', 'bio', 'categories', 'rating_avg',
            'total_reviews', 'completed_jobs_count', 'hourly_rate',
            'address', 'city', 'country', 'availability_status',
            'is_verified', 'avatar', 'display_name'
        ]
        read_only_fields = ['uuid', 'rating_avg', 'total_reviews', 'completed_jobs_count']


class DServiceSerializer(serializers.ModelSerializer):
    """Service listing"""
    provider = DServiceProviderProfileSerializer(read_only=True)
    category = DServiceCategorySerializer(read_only=True)  # source defaults to field name

    class Meta:
        model = DService
        fields = [
            'uuid', 'provider', 'category', 'name', 'description',
            'price', 'duration_minutes', 'thumbnail', 'created_at', 'updated_at'
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']


class DServiceDetailSerializer(DServiceSerializer):
    """Detailed service with comments"""
    comments_count = serializers.SerializerMethodField()
    average_rating = serializers.SerializerMethodField()

    def get_comments_count(self, obj):
        return obj.comments_DService.count()

    def get_average_rating(self, obj):
        comments = obj.comments_DService.all()
        if comments:
            return sum(c.rating for c in comments) / len(comments)
        return 0

    class Meta(DServiceSerializer.Meta):
        fields = DServiceSerializer.Meta.fields + ['comments_count', 'average_rating']


class DServiceRequestSerializer(serializers.ModelSerializer):
    """Service request"""
    client = UserSerializer(read_only=True)
    required_skills = SkillSerializer(many=True, read_only=True)

    class Meta:
        model = DServiceRequest
        fields = [
            'uuid', 'client', 'required_skills', 'title', 'description',
            'budget_min', 'budget_max', 'deadline', 'created_at', 'is_open'
        ]
        read_only_fields = ['uuid', 'created_at']


class DServiceProposalSerializer(serializers.ModelSerializer):
    """Service proposal"""
    provider = DServiceProviderProfileSerializer(read_only=True)
    request = DServiceRequestSerializer(read_only=True)

    class Meta:
        model = DServiceProposal
        fields = [
            'id', 'request', 'provider', 'proposed_rate',
            'message', 'submitted_at', 'is_accepted'
        ]
        read_only_fields = ['id', 'submitted_at', 'is_accepted']


class DServiceContractSerializer(serializers.ModelSerializer):
    """Service contract"""
    provider = DServiceProviderProfileSerializer(read_only=True)
    client = UserSerializer(read_only=True)

    class Meta:
        model = DServiceContract
        fields = [
            'id', 'provider', 'client', 'agreed_rate', 'agreed_deadline',
            'status', 'created_at', 'started_at', 'completed_at'
        ]
        read_only_fields = ['id', 'created_at', 'started_at', 'completed_at']


class DServiceCommentSerializer(serializers.ModelSerializer):
    """Service review/comment"""
    reviewer = UserSerializer(read_only=True)

    class Meta:
        model = DServiceComment
        fields = [
            'id', 'reviewer', 'content', 'rating',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# ==================== APPOINTMENT SERIALIZERS ====================

class AppointmentSerializer(serializers.ModelSerializer):
    """Appointment serializer"""
    user = UserSerializer(read_only=True)

    class Meta:
        model = Appointment
        fields = [
            'id', 'user', 'title', 'description', 'start_time',
            'end_time', 'status', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


# ==================== COMPANY SERIALIZERS ====================

class CompanySerializer(serializers.ModelSerializer):
    """Company serializer"""
    owner = UserSerializer(read_only=True)

    class Meta:
        model = Company
        fields = [
            'id', 'name', 'owner', 'description', 'website',
            'email', 'phone', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
