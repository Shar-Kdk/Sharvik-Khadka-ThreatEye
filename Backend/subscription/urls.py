from django.urls import path
from .views import get_plans, initiate_payment, payment_callback, subscription_status

urlpatterns = [
    path('plans/', get_plans, name='get_plans'),
    path('initiate/', initiate_payment, name='initiate_payment'),
    path('callback/', payment_callback, name='payment_callback'),
    path('status/', subscription_status, name='subscription_status'),
]