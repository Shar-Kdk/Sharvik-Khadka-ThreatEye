from django.db import models
from django.utils import timezone

class SubscriptionPlan(models.Model):
    PLAN_CHOICES = [
        ('basic', 'Basic Plan'),
        ('professional', 'Professional Plan'),
    ]
    name = models.CharField(max_length=50, choices=PLAN_CHOICES, unique=True)
    display_name = models.CharField(max_length=100, default='')
    max_users = models.PositiveIntegerField()
    email_alerts_enabled = models.BooleanField(default=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.display_name} ({self.price} NPR)"

    class Meta:
        ordering = ['price']


class Subscription(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
    ]
    organization = models.OneToOneField('authentication.Organization', on_delete=models.CASCADE, related_name='subscription', null=True, blank=True)
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    khalti_transaction_id = models.CharField(max_length=255, blank=True, null=True)
    khalti_pidx = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_active(self):
        return self.status == 'active'

    def __str__(self):
        org_name = self.organization.name if self.organization else "No Org"
        plan_name = self.plan.display_name if self.plan else "No Plan"
        return f"{org_name} - {plan_name}"

    class Meta:
        ordering = ['-created_at']