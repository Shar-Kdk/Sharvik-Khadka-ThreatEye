

from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, Organization


# ===== AUTHENTICATION SERIALIZERS =====
# Data validation for login, user registration, email verification

class LoginSerializer(serializers.Serializer):
    # Authenticate email/password, confirm account is active
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        # Validate email and password both provided
        email = data.get('email')
        password = data.get('password')
        
        if email and password:
            # Authenticate using email as username (custom User model)
            user = authenticate(username=email, password=password)
            
            # Check authentication succeeded
            if not user:
                raise serializers.ValidationError("Invalid email or password")
            # Verify account is active (not disabled by admin)
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
        else:
            raise serializers.ValidationError("Must include email and password")
        
        data['user'] = user
        return data


# ===== USER SERIALIZER =====
# Return user profile data including organization context
class UserSerializer(serializers.ModelSerializer):
    # Serialize user profile with organization context
    
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
        # Return full organization object with subscription tier
        if obj.organization:
            return {
                'id': obj.organization.id,
                'name': obj.organization.name,
                'subscription_tier': obj.organization.subscription_tier,
                'is_active': obj.organization.is_active
            }
        return None


# ===== ORGANIZATION SERIALIZER =====
# Return organization data with user capacity info
class OrganizationSerializer(serializers.ModelSerializer):
    # Return organization with user capacity info (current vs max)
    
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
        # Count active users in organization
        return obj.get_user_count()
    
    def get_can_add_user(self, obj):
        # Check if org can add users based on subscription tier
        return obj.can_add_user()


# ===== EMAIL VERIFICATION SERIALIZER =====
# Validate email verification code submission
class EmailVerificationSerializer(serializers.Serializer):
    # Validate 6-digit code, check email exists and not already verified
    
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    
    def validate(self, data):
        email = data.get('email')
        code = data.get('code')
        
        # Verify user account exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Don't allow re-verification of verified accounts
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        # Verify code matches and hasn't expired (5 minutes)
        if not user.verify_code(code):
            raise serializers.ValidationError("Invalid or expired verification code")
        
        data['user'] = user
        return data


# ===== RESEND VERIFICATION SERIALIZER =====
# Request to resend email verification code
class ResendVerificationSerializer(serializers.Serializer):
    # Request new verification code, ensure email exists and not verified
    
    email = serializers.EmailField()
    
    def validate(self, data):
        email = data.get('email')
        
        # Verify user account exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Don't allow resend for already verified accounts
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        data['user'] = user
        return data
