

from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, Organization


class LoginSerializer(serializers.Serializer):
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        
        if email and password:
            user = authenticate(username=email, password=password)
            
            if not user:
                raise serializers.ValidationError("Invalid email or password")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
        else:
            raise serializers.ValidationError("Must include email and password")
        
        data['user'] = user
        return data


class UserSerializer(serializers.ModelSerializer):
    
    organization = serializers.SerializerMethodField()
    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        source='organization',
        write_only=True,
        required=False,
        allow_null=True
    )
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'role',
            'organization', 'organization_id', 'is_active', 
            'is_verified', 'date_joined'
        ]
        read_only_fields = ['id', 'date_joined', 'is_verified', 'role']
    
    def get_organization(self, obj):
        if obj.organization:
            return {
                'id': obj.organization.id,
                'name': obj.organization.name,
                'subscription_tier': obj.organization.subscription_tier,
                'is_active': obj.organization.is_active
            }
        return None


class OrganizationSerializer(serializers.ModelSerializer):
    
    user_count = serializers.SerializerMethodField()
    can_add_user = serializers.SerializerMethodField()
    
    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'created_at', 'is_active', 
            'subscription_tier', 'max_users', 'user_count', 'can_add_user'
        ]
        read_only_fields = ['id', 'created_at', 'user_count', 'can_add_user']
    
    def get_user_count(self, obj):
        return obj.get_user_count()
    
    def get_can_add_user(self, obj):
        return obj.can_add_user()


class EmailVerificationSerializer(serializers.Serializer):
    
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    
    def validate(self, data):
        email = data.get('email')
        code = data.get('code')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        if not user.verify_code(code):
            raise serializers.ValidationError("Invalid or expired verification code")
        
        data['user'] = user
        return data


class ResendVerificationSerializer(serializers.Serializer):
    
    email = serializers.EmailField()
    
    def validate(self, data):
        email = data.get('email')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        data['user'] = user
        return data
