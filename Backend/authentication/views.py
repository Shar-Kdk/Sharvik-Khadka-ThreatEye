"""Authentication API endpoints for login, email verification, and user profiles."""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, UserSerializer, EmailVerificationSerializer, ResendVerificationSerializer
from .email_utils import send_verification_email
from .models import User, Organization


class LoginView(APIView):
    def post(self, request):
        """Authenticate user and return JWT token."""
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate JWT token for user
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Login successful',
                'user': UserSerializer(user).data,
                'token': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def post(self, request):
        """Verify email with verification code."""
        serializer = EmailVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Mark user as verified and clear verification data
            user.is_verified = True
            user.verification_code = None
            user.code_expires_at = None
            user.save()

            # Generate new JWT token for the verified user
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Email verified successfully',
                'user': UserSerializer(user).data,
                'token': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationCodeView(APIView):
    def post(self, request):
        """Generate new verification code and send email."""
        serializer = ResendVerificationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
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


