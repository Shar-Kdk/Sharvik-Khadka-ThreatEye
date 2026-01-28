from django.urls import path
from .views import (
    get_plans,
    CreatePaymentIntentView,
    VerifyPaymentView,
    PaymentListView,
    get_payment_history,
    subscription_status,
)

# ===== SUBSCRIPTION & PAYMENT API ENDPOINTS =====
# Following React-Django-Stripe-Backend pattern
urlpatterns = [
    # GET: List all available subscription plans
    path('plans/', get_plans, name='get_plans'),

    # POST: { plan_id } → Create Stripe PaymentIntent → return clientSecret
    path('create-payment-intent/', CreatePaymentIntentView.as_view(), name='create_payment_intent'),

    # POST: { payment_intent_id } → Verify payment succeeded → activate org subscription
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify_payment'),

    # GET: List all payments (admin sees all, user sees own)
    path('payments/', PaymentListView.as_view(), name='payment_list'),

    # GET: Payment history for current user (last 20)
    path('payment-history/', get_payment_history, name='get_payment_history'),

    # GET: Current subscription status for authenticated user
    path('status/', subscription_status, name='subscription_status'),
]
