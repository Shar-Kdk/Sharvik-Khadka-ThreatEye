from django.db import models
from django.utils import timezone


class SubscriptionPlan(models.Model):
    """
    Defines subscription tiers with features and pricing.
    Examples: Basic ($5/mo), Professional ($15/mo)
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

    def get_tier_key(self):
        """Return the canonical subscription tier for this plan."""
        if self.max_users <= 5 or self.price <= 5:
            return 'basic'
        return 'professional'

    def get_tier_label(self):
        """Return a user-friendly plan label for the UI."""
        return 'Basic plan' if self.get_tier_key() == 'basic' else 'Professional plan'

    class Meta:
        ordering = ['price']


class Payment(models.Model):
    """
    Track individual Stripe payments.
    Following the React-Django-Stripe-Backend pattern:
    amount, currency, stripe_payment_id, user_email
    Extended with plan + organization for ThreatEye subscription activation.
    """
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default='usd')
    stripe_payment_id = models.CharField(max_length=255, blank=True, null=True)
    user_email = models.EmailField()
    plan = models.ForeignKey(
        SubscriptionPlan,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        help_text='Plan purchased'
    )
    organization = models.ForeignKey(
        'authentication.Organization',
        on_delete=models.CASCADE,
        null=True, blank=True,
        help_text='Organization making payment'
    )
    status = models.CharField(
        max_length=20,
        default='pending',
        choices=[
            ('pending', 'Pending'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment {self.stripe_payment_id} - {self.amount} {self.currency}"

    class Meta:
        ordering = ['-created_at']
