"""Authentication Signals

This module contains Django signals for automatic user verification workflows.
Handles email verification for regular users and auto-verification for superusers.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User
from .email_utils import send_verification_email


@receiver(post_save, sender=User)
def send_email_verification(sender, instance, created, **kwargs):
    
    # Skip signal for fixtures/migrations
    if kwargs.get('raw', False):
        return
    
    # Only process newly created users
    if created:
        if instance.is_superuser:
            # SUPERUSER WORKFLOW
            # Automatically verify superusers without sending email
            if not instance.is_verified:
                instance.is_verified = True
                instance.save(update_fields=['is_verified'])
        elif not instance.is_verified:
            # Check if email was already sent (by admin form)
            if hasattr(instance, '_email_already_sent') and instance._email_already_sent:
                # Email already sent by admin form, skip
                return
            
            # REGULAR USER WORKFLOW (created via API/code, not admin)
            # Send verification email
            send_verification_email(instance)
