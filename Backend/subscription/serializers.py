from rest_framework import serializers
from .models import Payment, SubscriptionPlan


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """Serialize SubscriptionPlan model"""
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'display_name', 'max_users', 'email_alerts_enabled', 'price', 'created_at']
        read_only_fields = ['created_at']


class PaymentSerializer(serializers.ModelSerializer):
    """
    Serialize Payment model
    Following React-Django-Stripe-Backend pattern:
    id, amount, currency, stripe_payment_id, user_email, created_at
    Extended with plan_name, organization, status for ThreatEye
    """
    plan_name = serializers.CharField(source='plan.display_name', read_only=True)

    class Meta:
        model = Payment
        fields = [
            'id', 'amount', 'currency', 'stripe_payment_id',
            'user_email', 'plan', 'plan_name', 'organization',
            'status', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
