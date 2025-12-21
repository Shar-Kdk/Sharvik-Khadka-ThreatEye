#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ThreatEye.settings')
django.setup()

from authentication.models import User

# Delete invalid users
invalid_emails = ['gighj@ihih.kda', 'dadad@dad.com']

for email in invalid_emails:
    try:
        user = User.objects.get(email=email)
        user.delete()
        print(f"✓ Deleted user: {email}")
    except User.DoesNotExist:
        print(f"✗ User not found: {email}")
