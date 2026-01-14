from django.urls import path
from .views import get_plans, initiate_payment, verify_payment, subscription_status, get_platform_stats, get_subscription_history

urlpatterns = [
    path('plans/', get_plans, name='get_plans'),
    path('initiate/', initiate_payment, name='initiate_payment'),
    path('verify/', verify_payment, name='verify_payment'),
    path('status/', subscription_status, name='subscription_status'),
    path('history/', get_subscription_history, name='get_subscription_history'),
    path('platform-stats/', get_platform_stats, name='platform_stats'),
]
