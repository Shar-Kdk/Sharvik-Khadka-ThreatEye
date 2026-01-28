from django.contrib import admin
from .models import SubscriptionPlan, Payment


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ['display_name', 'max_users', 'price', 'email_alerts_enabled']
    ordering = ['price']


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['stripe_payment_id', 'user_email', 'amount', 'currency', 'plan', 'organization', 'status', 'created_at']
    list_filter = ['status', 'plan']
    search_fields = ['user_email', 'stripe_payment_id']
    readonly_fields = ['created_at']
