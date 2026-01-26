from django.urls import path
from .views import LoginView, LogoutView, UserProfileView, VerifyEmailView, ResendVerificationCodeView

# ===== AUTHENTICATION API ENDPOINTS =====
# Email-based authentication with email verification
urlpatterns = [
    # POST: email, password → JWT token, user data
    path('login/', LoginView.as_view(), name='login'),
    # POST: email, verification_code → verify account, enable login
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    # POST: email → send new verification code (5-minute validity)
    path('resend-verification/', ResendVerificationCodeView.as_view(), name='resend-verification'),
    # GET: requires JWT token, logs user out
    path('logout/', LogoutView.as_view(), name='logout'),
    # GET: requires JWT token, returns current user's profile data
    path('profile/', UserProfileView.as_view(), name='profile'),
]
