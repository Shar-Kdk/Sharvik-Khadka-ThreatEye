"""Authentication API Views

This module contains all API endpoints for user authentication and verification.
Provides REST endpoints for login, email verification, and user profile management.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, UserSerializer, EmailVerificationSerializer, ResendVerificationSerializer
from .email_utils import send_verification_email


class LoginView(APIView):
    """User Login Endpoint
    
    Authenticates users with email and password, returns JWT access token.
    Users can login even if email is not verified - frontend will show
    verification screen instead of dashboard for unverified users.
    
    Endpoint: POST /api/auth/login/
    
    Request Body:
        {
            "email": "user@example.com",
            "password": "password123"
        }
    
    Success Response (200):
        {
            "message": "Login successful",
            "user": {
                "id": 1,
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "is_active": true,
                "is_verified": false,
                "date_joined": "2025-12-20T14:30:00Z"
            },
            "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
        }
    
    Error Response (400):
        {
            "non_field_errors": ["Invalid email or password"]
        }
    """
    
    def post(self, request):
        """Authenticate user and return JWT token"""
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate JWT token for user
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Login successful',
                'user': UserSerializer(user).data,
                'token': str(refresh.access_token),  # 1-hour validity
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """Email Verification Endpoint
    
    Verifies user's email address using the 6-digit code sent via email.
    Code is valid for 5 minutes. After successful verification, user's
    is_verified flag is set to True and verification code is cleared.
    
    Endpoint: POST /api/auth/verify-email/
    
    Request Body:
        {
            "email": "user@example.com",
            "code": "123456"
        }
    
    Success Response (200):
        {
            "message": "Email verified successfully",
            "user": {
                "id": 1,
                "email": "user@example.com",
                "is_verified": true,
                ...
            }
        }
    
    Error Response (400):
        {
            "non_field_errors": ["Invalid or expired verification code"]
        }
    """
    
    def post(self, request):
        """Verify email with provided code"""
        serializer = EmailVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Mark user as verified and clear verification data
            user.is_verified = True
            user.verification_code = None
            user.code_expires_at = None
            user.save()
            
            return Response({
                'message': 'Email verified successfully',
                'user': UserSerializer(user).data,
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationCodeView(APIView):
    """Resend Verification Code Endpoint
    
    Generates a new 6-digit verification code and sends it to user's email.
    Can be used when original code expires or user doesn't receive the email.
    
    Endpoint: POST /api/auth/resend-verification/
    
    Request Body:
        {
            "email": "user@example.com"
        }
    
    Success Response (200):
        {
            "message": "Verification code sent to email",
            "email": "user@example.com"
        }
    
    Error Response (400):
        {
            "non_field_errors": ["Email is already verified"]
        }
    
    Error Response (500):
        {
            "error": "Failed to send verification email. Please try again."
        }
    """
    
    def post(self, request):
        """Generate new code and send verification email"""
        serializer = ResendVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Send new verification email (generates new code automatically)
            if send_verification_email(user):
                return Response({
                    'message': 'Verification code sent to email',
                    'email': user.email,
                }, status=status.HTTP_200_OK)
            else:
                # Email sending failed (SMTP error, etc.)
                return Response({
                    'error': 'Failed to send verification email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """User Logout Endpoint
    
    Logs out authenticated user. Note: With JWT tokens, actual logout
    is handled on frontend by clearing the token. This endpoint just
    confirms logout action.
    
    Requires: Authentication (Bearer token)
    Endpoint: POST /api/auth/logout/
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    
    Success Response (200):
        {
            "message": "Logout successful"
        }
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Confirm logout (frontend clears token)"""
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    """User Profile Endpoint
    
    Retrieves authenticated user's profile information.
    
    Requires: Authentication (Bearer token)
    Endpoint: GET /api/auth/profile/
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    
    Success Response (200):
        {
            "id": 1,
            "email": "user@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "is_active": true,
            "is_verified": true,
            "date_joined": "2025-12-20T14:30:00Z"
        }
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Return authenticated user's profile data"""
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
