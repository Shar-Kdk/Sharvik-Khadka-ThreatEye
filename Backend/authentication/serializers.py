"""Authentication Serializers

This module contains DRF serializers for authentication-related API endpoints.
Handles validation and data transformation for login, verification, and user data.
"""

from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User


class LoginSerializer(serializers.Serializer):
    """Serializer for user login with email and password
    
    Validates credentials using Django's authentication backend.
    Allows login even if email is not verified (frontend handles verification flow).
    
    Fields:
        email (str): User's email address
        password (str): User's password (write-only, not included in responses)
    """
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        """Validate login credentials
        
        Args:
            data (dict): Request data containing email and password
            
        Returns:
            dict: Validated data with authenticated user instance
            
        Raises:
            ValidationError: If credentials are invalid or account is disabled
        """
        email = data.get('email')
        password = data.get('password')
        
        if email and password:
            # Authenticate user with email/password
            user = authenticate(username=email, password=password)
            
            if not user:
                raise serializers.ValidationError("Invalid email or password")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
            
            # Note: We allow login even if email is not verified
            # Frontend will show verification screen instead of dashboard
        else:
            raise serializers.ValidationError("Must include email and password")
        
        # Add user instance to validated data
        data['user'] = user
        return data


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user profile data
    
    Returns user information for authenticated endpoints.
    Excludes sensitive fields like password and verification codes.
    
    Fields:
        id: User's unique identifier (read-only)
        email: User's email address
        first_name: User's first name
        last_name: User's last name
        is_active: Whether account is active
        is_verified: Whether email is verified (read-only)
        date_joined: Account creation date (read-only)
    """
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'is_active', 'is_verified', 'date_joined']
        read_only_fields = ['id', 'date_joined', 'is_verified']


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification with 6-digit code
    
    Validates the verification code against the user's stored code
    and checks if it has expired (5-minute validity).
    
    Fields:
        email (str): User's email address
        code (str): 6-digit verification code
    """
    
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    
    def validate(self, data):
        """Validate email and verification code
        
        Args:
            data (dict): Request data containing email and code
            
        Returns:
            dict: Validated data with user instance
            
        Raises:
            ValidationError: If user not found, already verified, or code invalid/expired
        """
        email = data.get('email')
        code = data.get('code')
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Check if already verified
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        # Verify code (checks match and expiry)
        if not user.verify_code(code):
            raise serializers.ValidationError("Invalid or expired verification code")
        
        # Add user instance to validated data
        data['user'] = user
        return data


class ResendVerificationSerializer(serializers.Serializer):
    """Serializer for resending verification code
    
    Validates that user exists and is not already verified
    before allowing a new code to be sent.
    
    Fields:
        email (str): User's email address
    """
    
    email = serializers.EmailField()
    
    def validate(self, data):
        """Validate user eligibility for code resend
        
        Args:
            data (dict): Request data containing email
            
        Returns:
            dict: Validated data with user instance
            
        Raises:
            ValidationError: If user not found or already verified
        """
        email = data.get('email')
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        
        # Check if already verified (no need to resend)
        if user.is_verified:
            raise serializers.ValidationError("Email is already verified")
        
        # Add user instance to validated data
        data['user'] = user
        return data
