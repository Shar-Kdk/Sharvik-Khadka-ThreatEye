from django.urls import path
from .views import get_plans, initiate_payment, verify_payment, subscription_status, get_platform_stats, get_subscription_history

# ===== SUBSCRIPTION & PAYMENT API ENDPOINTS =====
# Manage subscription plans, process Stripe payments, track subscription status
urlpatterns = [
    # GET: → list all subscription plans (Basic, Professional) with price and features
    path('plans/', get_plans, name='get_plans'),
    # POST: plan_id → create Stripe payment intent, return client secret for frontend
    path('initiate/', initiate_payment, name='initiate_payment'),
    # POST: payment_intent_id → verify payment completed, activate subscription
    path('verify/', verify_payment, name='verify_payment'),
    # GET: requires JWT → current user's subscription status (active/pending/expired)
    path('status/', subscription_status, name='subscription_status'),
    # GET: requires JWT → billing history for current organization
    path('history/', get_subscription_history, name='get_subscription_history'),
    # GET: requires admin token → platform-wide statistics (total users, revenue, etc.)
    path('platform-stats/', get_platform_stats, name='platform_stats'),
]
