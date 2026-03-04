from rest_framework import serializers
from .models import Payment, SubscriptionPlan


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """Serialize SubscriptionPlan model"""
    tier_label = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'display_name', 'tier_label', 'max_users', 'email_alerts_enabled', 'price', 'created_at']
        read_only_fields = ['created_at']

    def get_tier_label(self, obj):
        return obj.get_tier_label()


class PaymentSerializer(serializers.ModelSerializer):
    """
    Serialize Payment model
    Following React-Django-Stripe-Backend pattern:
    id, amount, currency, stripe_payment_id, user_email, created_at
    Extended with plan_name, organization, status for ThreatEye
    """
    plan_name = serializers.SerializerMethodField()

    class Meta:
        model = Payment
        fields = [
            'id', 'amount', 'currency', 'stripe_payment_id',
            'user_email', 'plan', 'plan_name', 'organization',
            'status', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def get_plan_name(self, obj):
        if obj.plan:
            return obj.plan.get_tier_label()
        return None
