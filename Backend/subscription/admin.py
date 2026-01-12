from django.contrib import admin
from .models import SubscriptionPlan, Subscription

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ['display_name', 'max_users', 'price', 'email_alerts_enabled']
    ordering = ['price']

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ['organization', 'plan', 'status', 'start_date', 'khalti_transaction_id']
    list_filter = ['status', 'plan']
    search_fields = ['organization__name', 'khalti_transaction_id']
    readonly_fields = ['khalti_transaction_id', 'khalti_pidx', 'created_at', 'updated_at']