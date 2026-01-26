from django.db import models
from django.utils import timezone

class SubscriptionPlan(models.Model):
    """
    Defines subscription tiers with features and pricing.
    Examples: Basic ($9.99), Professional ($29.99)
    """
    
    # Human-readable plan name
    display_name = models.CharField(
        max_length=100,
        unique=True,
        help_text='Plan name (e.g., Basic plan, Professional plan)'
    )
    # How many users this plan allows
    max_users = models.PositiveIntegerField(help_text='Maximum number of users for this plan')
    # Whether email alert notifications are enabled on this plan
    email_alerts_enabled = models.BooleanField(default=True, help_text='Enable email alerts for this plan')
    # Monthly subscription price in USD
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text='Monthly price in USD')
    # When this plan was created
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.display_name} (${self.price} USD)"

    class Meta:
        ordering = ['price']


class Subscription(models.Model):
    """
    Tracks each organization's subscription status.
    Linked to Stripe for payment processing.
    """
    
    # Subscription states: pending (awaiting payment)
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
    ]
    # The organization that has this subscription
    organization = models.OneToOneField('authentication.Organization', on_delete=models.CASCADE, related_name='subscription', null=True, blank=True)
    # The subscription plan this org chose
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT, null=True, blank=True)
    # Current status (pending, active, expired, cancelled)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    # When subscription starts
    start_date = models.DateTimeField(null=True, blank=True)
    # When subscription ends
    end_date = models.DateTimeField(null=True, blank=True)
    # Stripe payment intent ID for tracking the payment
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    # When subscription was created
    created_at = models.DateTimeField(auto_now_add=True)
    # When subscription was last updated
    updated_at = models.DateTimeField(auto_now=True)

    def is_active(self):
        return self.status == 'active'

    def __str__(self):
        org_name = self.organization.name if self.organization else "No Org"
        plan_name = self.plan.display_name if self.plan else "No Plan"
        return f"{org_name} - {plan_name}"

    class Meta:
        ordering = ['-created_at']
