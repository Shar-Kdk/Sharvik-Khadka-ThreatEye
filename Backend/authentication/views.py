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
    
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Confirm logout (frontend clears token)"""
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Return authenticated user's profile data"""
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
